#!/usr/bin/env python3
"""Installer safety tests; fake sysfs, block topology, firmware and GRUB, no root needed."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("installer", ROOT / "tools/install/install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class Machine:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.fail = None
        self.target = "multi-user.target"
        self.display_manager = "not-found"
        self.boot = dict(order="0001,0002", current="0001", next=None,
                         entries={"0001": "Linux\tHD(native)", "0002": "Recovery\tHD(recovery)"})
        self.write("/sys/firmware/efi/fw_platform_size", "64")
        self.write("/sys/firmware/efi/efivars/SecureBoot-" + installer.EFI_GLOBAL, b"\x07\0\0\0\0")
        self.write("/sys/firmware/acpi/tables/APIC", "MADT")
        self.write("/proc/cpuinfo", "processor: 0\nvendor_id: GenuineIntel\napicid: 0\nflags: " +
                   " ".join(installer.CPU_FLAGS | {"arch_capabilities", "pcid", "x2apic"}))
        self.write("/proc/meminfo", "MemTotal: 8388608 kB")
        self.write("/proc/1/comm", "systemd")
        self.write("/sys/devices/system/cpu/vulnerabilities/meltdown", "Not affected")
        self.write("/sbin/init", "init", 0o755)
        for path in ("/lib/modules", "/dev", "/proc", "/sys", "/run", "/usr", "/etc", "/boot/efi"):
            self.path(path).mkdir(parents=True, exist_ok=True)
        self.pci("00:04.0", 0x1AF4, 0x1042, 0x010000)
        self.links = [dict(ifname="lo", link_type="loopback")]
        self.nic("ens3", "00:05.0", "52:54:00:12:34:56")
        disk = self.path("/sys/devices/pci0000:00/0000:00:04.0/virtio0/block/vda")
        disk.mkdir(parents=True)
        self.link("/sys/class/block/vda", disk)
        self.write("/sys/class/block/vda1/partition", "1")
        self.blocks = [
            dict(name="/dev/vda", type="disk", pkname=None, pttype="gpt", **{"maj:min": "252:0"}),
            dict(name="/dev/vda1", type="part", pkname="/dev/vda", fstype="vfat", uuid="ABCD-1234",
                 parttype=installer.ESP_TYPE, partuuid="aabbccdd-0011-2233-4455-66778899aabb", **{"maj:min": "252:1"}),
            dict(name="/dev/vda2", type="part", pkname="/dev/vda", fstype="ext4", uuid="1234-abcd",
                 **{"maj:min": "252:2"}),
        ]
        self.mounts = [dict(source="/dev/vda2", target="/", fstype="ext4", options="rw,relatime", **{"maj:min": "252:2"}),
                       dict(source="/dev/vda1", target="/boot/efi", fstype="vfat", options="rw,relatime", **{"maj:min": "252:1"})]
        self.fstab = [dict(source="UUID=1234-abcd", target="/", fstype="ext4", options="defaults"),
                      dict(source="UUID=ABCD-1234", target="/boot/efi", fstype="vfat", options="defaults")]

    def path(self, path):
        return self.root / str(path).lstrip("/")

    def write(self, path, value, mode=0o644):
        dest = self.path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(value.encode() if isinstance(value, str) else value)
        dest.chmod(mode)

    def link(self, path, target):
        dest = self.path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.symlink_to(target)

    def pci(self, bdf, vendor, device, cls, msix=True, modern=True):
        base = "/sys/devices/pci0000:00/0000:" + bdf
        for name, value in (("vendor", vendor), ("device", device), ("class", cls)):
            self.write(base + "/" + name, hex(value))
        config = bytearray(256)
        config[0x34] = 0x40
        config[0x40:0x44] = bytes([0x11 if msix else 1, 0x50, 3, 0])
        config[0x50:0x54] = bytes([9 if modern else 1, 0, 16, 1])
        self.write(base + "/config", config)
        self.write(base + "/resource", "0x1000 0x5fff 0x200\n" * 6)

    def nic(self, name, bdf, mac):
        self.pci(bdf, 0x1AF4, 0x1041, 0x020000)
        self.link("/sys/class/net/" + name + "/device", self.path("/sys/devices/pci0000:00/0000:" + bdf))
        self.write("/sys/class/net/" + name + "/addr_assign_type", "0")
        self.write("/sys/class/net/" + name + "/address", mac)
        self.links.append(dict(ifname=name, link_type="ether"))

    def command(self, *args):
        self.calls.append(args)
        if args[0] == "findmnt":
            if "--fstab" in args:
                rows = self.fstab
            elif "--target" in args:
                target = args[args.index("--target") + 1]
                if target == "/sys/firmware/efi/efivars":
                    rows = [dict(target=target, source="efivarfs", fstype="efivarfs", options="rw")]
                else:
                    # The filesystem holding the path: the longest mount point above it.
                    above = [m for m in self.mounts if (target + "/").startswith(m["target"].rstrip("/") + "/")]
                    rows = [max(above, key=lambda m: len(m["target"]))]
            else:
                rows = self.mounts
            return json.dumps(dict(filesystems=rows))
        if args[0] == "lsblk":
            return json.dumps(dict(blockdevices=self.blocks))
        if args[0] == "ip":
            return json.dumps(self.links)
        if args[0] == "systemctl":
            return self.target if args[1] == "get-default" else self.display_manager
        if args[0] == "efibootmgr":
            if args[1] == "--verbose":
                text = "BootOrder: {}\nBootCurrent: {}\n".format(self.boot["order"], self.boot["current"])
                if self.boot["next"]:
                    text += "BootNext: " + self.boot["next"] + "\n"
                return text + "\n".join("Boot{}* {}".format(n, v) for n, v in self.boot["entries"].items())
            if "--create-only" in args:
                self.boot["entries"][args[args.index("--bootnum") + 1]] = (
                    "L4H\tHD(1,GPT,aabbccdd-0011-2233-4455-66778899aabb,0x800,0x80000)/File(" + installer.LOADER + ")")
            elif "--delete-bootnum" in args:
                self.boot["entries"].pop(args[args.index("--bootnum") + 1], None)
            elif "--bootorder" in args:
                self.boot["order"] = args[2]
            elif "--bootnext" in args:
                self.boot["next"] = args[2]
            elif "--delete-bootnext" in args:
                self.boot["next"] = None
            else:
                raise AssertionError(args)
            if self.fail and self.fail in args:
                self.fail = None  # Model failure after firmware changed state.
                raise installer.Incompatible("injected firmware failure")
            return ""
        if args[0] in ("grub-editenv", "grub2-editenv"):
            assert args[1] == "/boot/grub/grubenv", args
            if args[2] == "list":
                return "\n".join("{}={}".format(k, v) for k, v in self.grubenv.items())
            if args[2] == "set":
                key, value = args[3].split("=", 1)
                self.grubenv[key] = value
            elif args[2] == "unset":
                self.grubenv.pop(args[3], None)
            else:
                raise AssertionError(args)
            if self.fail and self.fail in args:
                self.fail = None
                raise installer.Incompatible("injected GRUB failure")
            return ""
        raise AssertionError(args)

    def bios(self):
        """The same machine booted by BIOS GRUB (e.g. a DigitalOcean droplet)."""
        shutil.rmtree(self.path("/sys/firmware/efi"), ignore_errors=True)
        self.write("/proc/cmdline", "BOOT_IMAGE=/boot/vmlinuz root=UUID=1234-abcd ro console=ttyS0")
        self.write("/boot/grub/grub.cfg",
                   "if [ \"${next_entry}\" ] ; then\n   set default=\"${next_entry}\"\nfi\n"
                   "if [ -f  ${config_directory}/custom.cfg ]; then\n  source ${config_directory}/custom.cfg\nfi\n")
        self.write("/boot/grub/grubenv", "# GRUB Environment Block\n" + "#" * 998)
        self.grubenv = {"saved_entry": "0"}
        mbr = bytearray(512)
        mbr[0x188:0x18d] = b"GRUB "
        mbr[510:] = b"\x55\xaa"
        self.write("/dev/vda", bytes(mbr))


class Harness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.machine = Machine(self.root)
        self.args = installer.arguments(["--check"])
        self.preflight = installer.Preflight(self.args, self.root, self.machine.command)
        self.sync = patch.object(installer.os, "sync")
        self.sync.start()
        self.addCleanup(self.sync.stop)

    def check(self):
        with patch.object(installer.platform, "system", return_value="Linux"), \
             patch.object(installer.platform, "machine", return_value="x86_64"):
            return self.preflight.check()

    def rejected(self, message):
        with self.assertRaisesRegex(installer.Incompatible, message):
            self.check()
        self.assertFalse(any(c[0] == "efibootmgr" and c[1] != "--verbose" for c in self.machine.calls))

    def package(self):
        for path in ("install/initrd", "bin/l4hctl", "share/licenses/l4hctl/LICENSE"):
            self.machine.write("/package/" + path, "release " + path)
        self.machine.write("/new.efi", "new EFI")
        return self.root / "package"

    def commit(self, plan=None, default=False):
        installer.commit(plan or self.check(), self.package(), self.root / "new.efi", "vtest", default,
                         root=self.root, command=self.machine.command)


class InstallerTests(Harness):
    def test_supported_machine_and_read_only_preflight(self):
        before = sorted(str(p) for p in self.root.rglob("*"))
        plan = self.check()
        self.assertEqual((plan["variant"], plan["root_uuid"]), ("generic", "1234-abcd"))
        self.assertEqual(plan["uplinks"], [dict(ifname="ens3", bdf="00:05.0", mac="52:54:00:12:34:56")])
        config = installer.configuration(plan)
        self.assertIn("root=UUID=1234-abcd", config)
        self.assertIn("l4h.net=52:54:00:12:34:56,ens3", config)
        self.assertIn("dom0_disks=15\ndom0_nics=1\n", config)
        self.assertNotIn("uplink2_nic", config)
        self.assertEqual(before, sorted(str(p) for p in self.root.rglob("*")))

    def test_secure_boot(self):
        self.machine.write("/sys/firmware/efi/efivars/SecureBoot-" + installer.EFI_GLOBAL, b"\x07\0\0\0\1")
        self.rejected("Secure Boot")

    def test_firmware_without_secure_boot_and_truncated_variable(self):
        name = "/sys/firmware/efi/efivars/SecureBoot-" + installer.EFI_GLOBAL
        self.machine.path(name).unlink()
        self.check()
        self.machine.write(name, b"\x07\0\0\0")
        self.rejected("Secure Boot")

    def test_mitigated_meltdown_is_not_unaffected(self):
        self.machine.write("/sys/devices/system/cpu/vulnerabilities/meltdown", "Mitigation: PTI")
        self.rejected("unaffected by Meltdown")

    def test_missing_cpu_feature(self):
        cpu = self.machine.path("/proc/cpuinfo")
        cpu.write_text(cpu.read_text().replace("xsaveopt", ""))
        self.rejected("xsaveopt")

    def test_variant_fallback_and_invalid_override(self):
        cpu = self.machine.path("/proc/cpuinfo")
        cpu.write_text(cpu.read_text().replace("pcid", ""))
        self.assertEqual(self.check()["variant"], "xapic-nopcid")
        self.args.variant = "generic"
        self.rejected("PCID")

    def test_ram_and_cpu_bounds(self):
        for memory, cpus in ((9000, None), (0, None), (None, 0), (None, 2)):
            with self.subTest(memory=memory, cpus=cpus):
                self.args.memory, self.args.vcpus = memory, cpus
                self.rejected("RAM|vCPUs")

    def test_lvm_and_unsupported_fs(self):
        self.machine.blocks[2]["type"] = "lvm"
        self.rejected("plain disks")
        self.machine.blocks[2]["type"] = "part"
        self.machine.mounts[0]["fstype"] = "btrfs"
        self.rejected("ext4 or XFS")

    def test_sata_and_legacy_virtio_blk(self):
        self.machine.pci("00:04.0", 0x8086, 0x2922, 0x010601)
        self.rejected("SATA")
        self.machine.pci("00:04.0", 0x1AF4, 0x1001, 0x010000, modern=False)
        self.rejected("modern virtio-blk")

    def test_msix_required(self):
        self.machine.pci("00:04.0", 0x1AF4, 0x1042, 0x010000, msix=False)
        self.rejected("MSI-X")

    def test_fstab_unstable_and_missing_device(self):
        self.machine.fstab[0]["source"] = "/dev/vda2"
        self.rejected("unstable source")
        self.machine.fstab[0]["source"] = "UUID=missing"
        self.rejected("missing or ambiguous")

    def test_duplicate_uuid(self):
        self.machine.blocks.append(dict(self.machine.blocks[2], name="/dev/vdb2"))
        self.machine.blocks[-1]["maj:min"] = "253:2"
        self.rejected("duplicated")

    def test_separate_usr(self):
        self.machine.mounts.append(dict(self.machine.mounts[1], target="/usr"))
        self.rejected("/usr must be on")

    def test_crypttab(self):
        self.machine.write("/etc/crypttab", "# comment\ncrypt UUID=abc none luks\n")
        self.rejected("crypttab")

    def test_unsupported_network_and_bridge(self):
        self.machine.pci("00:05.0", 0x8086, 0x100E, 0x020000)
        self.rejected("supported uplinks")
        self.machine.pci("00:05.0", 0x1AF4, 0x1041, 0x020000)
        self.machine.links.append(dict(ifname="br0", link_type="ether", linkinfo=dict(info_kind="bridge")))
        self.rejected("plain Ethernet uplink")

    def test_two_uplinks_have_separate_switches_and_stable_mac_mappings(self):
        self.machine.nic("ens2", "00:03.0", "52:54:00:12:34:57")
        plan = self.check()
        self.assertEqual(plan["uplinks"], [dict(ifname="ens2", bdf="00:03.0", mac="52:54:00:12:34:57"),
                                           dict(ifname="ens3", bdf="00:05.0", mac="52:54:00:12:34:56")])
        config = installer.configuration(plan)
        self.assertIn("uplink_nic=00:03.0\nuplink2_nic=00:05.0\n", config)
        # Two vNICs on switch 0 would connect both networks to the same switch.
        self.assertIn("dom0_disks=14\ndom0_nics=1\n", config)
        self.assertIn("l4h.net=52:54:00:12:34:57,ens2 l4h.net=52:54:00:12:34:56,ens3", config)
        self.machine.links.reverse()
        self.assertEqual(self.check(), plan)
        self.commit(plan)
        self.assertEqual(self.machine.path("/boot/efi/l4h/l4h.conf").read_text(), config)

    def test_zero_and_three_nics_rejected(self):
        self.machine.nic("ens4", "00:06.0", "52:54:00:12:34:57")
        self.machine.nic("ens5", "00:07.0", "52:54:00:12:34:58")
        self.rejected("one or two physical NICs")
        self.machine.links = self.machine.links[:1]
        self.rejected("one or two physical NICs")

    def test_second_nic_must_be_supported_unbridged_and_have_permanent_mac(self):
        self.machine.nic("ens4", "00:06.0", "52:54:00:12:34:57")
        self.machine.pci("00:06.0", 0x8086, 0x100E, 0x020000)
        self.rejected("ens4: supported uplinks")
        self.machine.pci("00:06.0", 0x1AF4, 0x1041, 0x020000)
        self.machine.links[-1]["master"] = "br0"
        self.rejected("ens4: need a plain Ethernet")
        del self.machine.links[-1]["master"]
        self.machine.write("/sys/class/net/ens4/addr_assign_type", "3")
        self.rejected("ens4: uplink MAC has been changed")

    def test_duplicate_uplink_mac_and_pci_rejected(self):
        self.machine.nic("ens4", "00:06.0", "52:54:00:12:34:56")
        self.rejected("distinct MAC addresses and PCI devices")
        self.machine.write("/sys/class/net/ens4/address", "52:54:00:12:34:57")
        self.machine.path("/sys/class/net/ens4/device").unlink()
        self.machine.link("/sys/class/net/ens4/device", self.machine.path("/sys/devices/pci0000:00/0000:00:05.0"))
        self.rejected("distinct MAC addresses and PCI devices")

    def test_invalid_uplink_mac_rejected(self):
        for mac in ("invalid", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "53:54:00:12:34:56"):
            with self.subTest(mac=mac):
                self.machine.write("/sys/class/net/ens3/address", mac)
                self.rejected("invalid Ethernet MAC")

    def test_disk_capacity_reserves_one_slot_per_uplink(self):
        disk = self.machine.blocks[0]
        self.machine.blocks.extend(dict(disk, name="/dev/disk{}".format(i)) for i in range(13))
        self.machine.nic("ens4", "00:06.0", "52:54:00:12:34:57")
        self.check()  # 14 disks and two vNICs fit.
        self.machine.blocks.append(dict(disk, name="/dev/extra"))
        self.rejected("at most 14 disks with 2 uplink")
        self.machine.links.pop()
        self.check()  # 15 disks and one vNIC fit.
        self.machine.blocks.append(dict(disk, name="/dev/extra2"))
        self.rejected("at most 15 disks with 1 uplink")

    def test_existing_bootnext(self):
        self.machine.boot["next"] = "0002"
        self.rejected("BootNext")

    def test_nvme_namespace_one_only(self):
        self.machine.pci("00:04.0", 0x1234, 0x0011, 0x010802)
        self.machine.write("/sys/class/block/vda/nsid", "1")
        self.check()
        self.machine.write("/sys/class/block/vda/nsid", "2")
        self.rejected("namespace 1")

    def test_apparmor_rejected_and_selinux_preserved(self):
        self.machine.write("/sys/fs/selinux/enforce", "1")
        self.assertIn("lsm=selinux enforcing=1", installer.configuration(self.check()))
        self.machine.write("/sys/kernel/security/apparmor/profiles", "test (enforce)")
        self.rejected("AppArmor")

    def test_headless_graphical_target(self):
        self.machine.target = "graphical.target"
        self.check()
        self.machine.display_manager = "loaded"
        self.rejected("headless")

    def test_ambiguous_esp(self):
        self.machine.mounts.append(dict(self.machine.mounts[1], target="/efi"))
        self.rejected("one mounted GPT")
        self.args.esp = "/boot/efi"
        self.assertEqual(self.check()["esp"], "/boot/efi")

    def test_install_preserves_native_files_and_order(self):
        self.machine.write("/boot/efi/EFI/BOOT/BOOTX64.EFI", "native fallback")
        self.commit()
        self.assertEqual(self.machine.boot["order"], "0001,0002")
        self.assertEqual(self.machine.boot["next"], "0000")
        self.assertEqual(self.machine.path("/boot/efi/EFI/BOOT/BOOTX64.EFI").read_text(), "native fallback")
        self.assertTrue(self.machine.path(installer.STATE).is_file())
        self.assertFalse(any(c[0] in ("reboot", "mkfs", "mount") for c in self.machine.calls))

    def test_update_reuses_entry_and_backup(self):
        self.commit()
        self.commit()
        self.assertEqual(len(self.machine.boot["entries"]), 3)
        self.assertEqual(len(list(self.machine.path("/var/lib/l4h/backups").iterdir())), 2)

    def test_existing_entry_on_wrong_esp(self):
        self.commit()
        self.machine.calls.clear()
        self.machine.boot["entries"]["0000"] = self.machine.boot["entries"]["0000"].replace("HD(1,", "HD(2,")
        self.rejected("different ESP")

    def test_make_default_keeps_previous_order(self):
        self.commit(default=True)
        self.assertEqual(self.machine.boot["order"], "0000,0001,0002")

    def test_firmware_failure_rolls_back_and_allows_retry(self):
        for failure in ("--create-only", "--bootnext", "--bootorder"):
            with self.subTest(failure=failure):
                original = copy.deepcopy(self.machine.boot)
                self.machine.fail = failure
                with self.assertRaisesRegex(installer.Incompatible, "injected"):
                    self.commit(default=failure == "--bootorder")
                self.assertEqual(self.machine.boot, original)
                self.assertFalse(self.machine.path(installer.STATE).exists())
                self.assertFalse(self.machine.path("/boot/efi/l4h").exists())
                self.check()

    def test_update_failure_restores_existing_payload(self):
        self.commit()
        original = copy.deepcopy(self.machine.boot)
        self.machine.write("/boot/efi/l4h/l4h.conf", "old configuration")
        self.machine.fail = "--bootnext"
        with self.assertRaises(installer.Incompatible):
            self.commit()
        self.assertEqual(self.machine.path("/boot/efi/l4h/l4h.conf").read_text(), "old configuration")
        self.assertEqual(self.machine.boot, original)

    def test_disk_full_before_efi(self):
        plan = self.check()
        self.package()
        original = copy.deepcopy(self.machine.boot)
        with patch.object(installer.shutil, "disk_usage") as usage:
            usage.return_value.free = 0
            with self.assertRaisesRegex(installer.Incompatible, "free space"):
                self.commit(plan)
        self.assertEqual(self.machine.boot, original)
        self.assertFalse(self.machine.path("/var/lib/l4h").exists())

    def test_file_copy_failure_before_efi(self):
        original = copy.deepcopy(self.machine.boot)
        real_copy = installer.atomic_copy
        def copy_or_fail(source, dest, mode):
            if dest.name == "initrd":
                raise OSError("disk full")
            real_copy(source, dest, mode)
        with patch.object(installer, "atomic_copy", side_effect=copy_or_fail):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.commit()
        self.assertEqual(self.machine.boot, original)
        self.assertFalse(self.machine.path("/boot/efi/EFI/L4H").exists())

    def test_changed_firmware_before_commit(self):
        plan = self.check()
        self.machine.boot["order"] = "0002,0001"
        with self.assertRaisesRegex(installer.Incompatible, "changed during"):
            self.commit(plan)
        self.assertFalse(self.machine.path("/boot/efi/l4h").exists())

    def test_concurrent_foreign_entry_is_not_deleted(self):
        plan = self.check()
        package = self.package()
        def racing_firmware(*args):
            if "--create-only" in args:
                self.machine.boot["entries"]["0000"] = "Other OS\tHD(other)"
                raise installer.Incompatible("boot number exists")
            return self.machine.command(*args)
        with self.assertRaisesRegex(installer.Incompatible, "boot number exists"):
            installer.commit(plan, package, self.root / "new.efi", "vtest", False,
                             root=self.root, command=racing_firmware)
        self.assertEqual(self.machine.boot["entries"]["0000"], "Other OS\tHD(other)")

    def test_symlink_destination(self):
        plan = self.check()
        self.machine.link("/usr/local", self.root / "outside")
        with self.assertRaisesRegex(installer.Incompatible, "symlink"):
            self.commit(plan)

    def test_bad_download_checksum(self):
        self.args.release = "vtest"
        self.args.checksums = self.root / "SHA256SUMS"
        self.args.checksums.write_text("0" * 64 + "  l4h-generic.efi\n")
        dest = self.root / "download.efi"
        dest.write_text("corrupt")
        with patch.object(installer, "run", return_value=""):
            with self.assertRaisesRegex(installer.Incompatible, "checksum mismatch"):
                installer.download_efi(self.args, self.check(), dest)

    def test_package_extraction_rejects_traversal_links_and_checksum(self):
        bootstrap = (ROOT / "tools/install.sh").read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        for kind in ("traversal", "symlink", "checksum"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                work = Path(temp)
                archive = work / "l4h-dom0-x86_64.tar.xz"
                with tarfile.open(archive, "w:xz") as tar:
                    info = tarfile.TarInfo("l4h-dom0-x86_64/../../escape" if kind == "traversal" else "l4h-dom0-x86_64/install.py")
                    if kind == "symlink":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "/etc/passwd"
                    tar.addfile(info, io.BytesIO(b""))
                checksum = "0" * 64 if kind == "checksum" else installer.digest(archive)
                (work / "SHA256SUMS").write_text(checksum + "  " + archive.name + "\n")
                result = subprocess.run(["python3", "-c", bootstrap, temp], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("l4h:", result.stderr)

    def test_pipe_help_and_bad_option(self):
        script = (ROOT / "tools/install.sh").read_bytes()
        result = subprocess.run(["bash", "-s", "--", "--help"], input=script, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"BootNext", result.stdout)
        result = subprocess.run(["bash", "-s", "--", "--unknown"], input=script, capture_output=True)
        self.assertEqual(result.returncode, 2)


def elf(multiboot2=False):
    header = bytearray(4096)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 18, 0x3E)
    if multiboot2:
        struct.pack_into("<I", header, 0x1000 - 32, 0xE85250D6)
    return bytes(header)


class BiosInstallerTests(Harness):
    def setUp(self):
        super().setUp()
        self.machine.bios()

    def bios_package(self):
        bios = self.root / "bios"
        for name in ("grub.cfg", "kmods.erofs"):
            self.machine.write("/bios/" + name, "release " + name)
        for name in ("l4h-root.elf", "vmlinux"):
            self.machine.write("/bios/" + name, elf())
        for variant in ("generic", "xapic-nopcid"):
            self.machine.write("/bios/kernel-" + variant + ".elf", elf(True) + variant.encode())
        return bios

    def commit(self, plan=None, default=False, command=None):
        installer.commit(plan or self.check(), self.package(), self.bios_package(), "vtest", default,
                         root=self.root, command=command or self.machine.command)

    def rejected(self, message):
        before = dict(self.machine.grubenv)
        super().rejected(message)
        self.assertEqual(self.machine.grubenv, before)

    def custom(self):
        return self.machine.path("/boot/grub/custom.cfg").read_text()

    def test_supported_bios_machine_and_read_only_preflight(self):
        before = sorted(str(p) for p in self.root.rglob("*"))
        plan = self.check()
        self.assertEqual((plan["firmware"], plan["grubdir"], plan["grub_tool"]), ("bios", "/boot/grub", "grub-editenv"))
        self.assertEqual((plan["boot_uuid"], plan["boot_fstype"], plan["grub_dir"]), ("1234-abcd", "ext4", "/boot/l4h"))
        self.assertNotIn("esp", plan)
        self.assertIn("root=UUID=1234-abcd", installer.configuration(plan))
        self.assertFalse(any(c[0] == "efibootmgr" for c in self.machine.calls))
        self.assertEqual(before, sorted(str(p) for p in self.root.rglob("*")))

    def test_separate_boot_partition(self):
        self.machine.blocks.append(dict(name="/dev/vda3", type="part", pkname="/dev/vda", fstype="xfs",
                                        uuid="5678-boot", **{"maj:min": "252:3"}))
        self.machine.mounts.append(dict(source="/dev/vda3", target="/boot", fstype="xfs", options="rw",
                                        **{"maj:min": "252:3"}))
        self.machine.fstab.append(dict(source="UUID=5678-boot", target="/boot", fstype="xfs", options="defaults"))
        plan = self.check()
        self.assertEqual((plan["boot_uuid"], plan["boot_fstype"], plan["grub_dir"]), ("5678-boot", "xfs", "/l4h"))
        entry = installer.grub_entry(plan, False)
        self.assertIn("insmod xfs\n", entry)
        self.assertIn("search --no-floppy --fs-uuid --set=root 5678-boot\n    set l4h=($root)/l4h\n", entry)

    def test_boot_filesystem_must_be_readable_and_writable_by_grub(self):
        self.machine.mounts.append(dict(self.machine.mounts[0], target="/boot", fstype="vfat"))
        self.rejected("ext2/3/4 or XFS")

    def test_grub_must_be_in_the_mbr_and_boot_linux(self):
        self.machine.write("/dev/vda", bytes(510) + b"\x55\xaa")
        self.rejected("MBR does not hold GRUB")
        self.machine.bios()
        self.machine.write("/proc/cmdline", "root=UUID=1234-abcd ro")
        self.rejected("booted by GRUB")

    def test_grub_configuration_must_come_from_grub_mkconfig(self):
        self.machine.write("/boot/grub/grub.cfg", "linux /vmlinuz\n")
        self.rejected("grub-mkconfig")
        self.machine.bios()
        self.machine.write("/boot/grub2/grub.cfg", "")
        self.rejected("exactly one")
        self.machine.path("/boot/grub2/grub.cfg").unlink()
        self.machine.path("/boot/grub/grubenv").unlink()
        self.rejected("environment block")

    def test_unmanaged_custom_cfg_and_pending_next_entry(self):
        self.machine.write("/boot/grub/custom.cfg", "menuentry 'Mine' {}\n")
        self.rejected("custom.cfg exists")
        self.machine.path("/boot/grub/custom.cfg").unlink()
        self.machine.grubenv["next_entry"] = "1"
        self.rejected("next_entry is already set")

    def test_unmanaged_files(self):
        self.machine.write("/boot/l4h/l4h.conf", "")
        self.rejected("unmanaged L4H files")

    def test_esp_is_not_needed(self):
        self.machine.mounts.append(dict(self.machine.mounts[1], target="/efi"))
        self.check()  # BIOS GRUB does not use an ESP.

    def test_install_selects_l4h_once_and_preserves_native_files(self):
        self.machine.write("/boot/vmlinuz", "native kernel")
        self.commit()
        self.assertEqual(self.machine.grubenv, {"saved_entry": "0", "next_entry": "l4h"})
        self.assertEqual(self.machine.path("/boot/vmlinuz").read_text(), "native kernel")
        bios = self.machine.path("/boot/l4h/bios")
        self.assertEqual(sorted(p.name for p in bios.iterdir()),
                         ["grub.cfg", "kernel.elf", "kmods.erofs", "l4h-root.elf", "vmlinux"])
        self.assertTrue((bios / "kernel.elf").read_bytes().endswith(b"generic"))
        self.assertEqual(self.machine.path("/boot/l4h/dom0/initrd").read_text(), "release install/initrd")
        self.assertIn("dom0_mem_mb=", self.machine.path("/boot/l4h/l4h.conf").read_text())
        custom = self.custom()
        self.assertTrue(custom.startswith(installer.GENERATED))
        self.assertIn("menuentry 'L4H' --id l4h {\n", custom)
        self.assertIn("search --no-floppy --fs-uuid --set=root 1234-abcd\n    set l4h=($root)/boot/l4h\n", custom)
        self.assertIn('source "$l4h/bios/grub.cfg"\n', custom)
        self.assertNotIn("set default", custom)
        state = json.loads(self.machine.path(installer.STATE).read_text())
        self.assertEqual(state, dict(firmware="bios", grubdir="/boot/grub", default=False, release="vtest"))
        self.assertFalse(any(c[0] in ("efibootmgr", "reboot", "grub-install", "update-grub", "grub-mkconfig")
                             for c in self.machine.calls))

    def test_xapic_variant_kernel(self):
        cpu = self.machine.path("/proc/cpuinfo")
        cpu.write_text(cpu.read_text().replace("pcid", ""))
        self.commit()
        self.assertTrue(self.machine.path("/boot/l4h/bios/kernel.elf").read_bytes().endswith(b"xapic-nopcid"))

    def test_update_reuses_entry_and_backup(self):
        self.commit()
        self.commit()
        self.assertEqual(self.machine.grubenv["next_entry"], "l4h")
        self.assertEqual(len(list(self.machine.path("/var/lib/l4h/backups").iterdir())), 2)

    def test_entry_without_state(self):
        self.commit()
        self.machine.path(installer.STATE).unlink()
        self.rejected("not managed by this installer")

    def test_make_default_and_a_later_trial(self):
        self.commit(default=True)
        self.assertEqual(self.machine.grubenv, {"saved_entry": "0"})
        self.assertIn('if [ -z "$boot_once" ]; then set default=l4h; fi\n', self.custom())
        # A later installation without --make-default keeps L4H the default,
        # as BootOrder does; next_entry would add nothing.
        self.commit()
        self.assertIn("set default=l4h", self.custom())
        self.assertEqual(self.machine.grubenv, {"saved_entry": "0"})

    def test_grub_env_failure_rolls_back_and_allows_retry(self):
        original = dict(self.machine.grubenv)
        self.machine.fail = "set"
        with self.assertRaisesRegex(installer.Incompatible, "injected"):
            self.commit()
        self.assertEqual(self.machine.grubenv, original)
        self.assertFalse(self.machine.path(installer.STATE).exists())
        self.assertFalse(self.machine.path("/boot/l4h").exists())
        self.assertFalse(self.machine.path("/boot/grub/custom.cfg").exists())
        self.check()

    def test_update_failure_restores_existing_payload(self):
        self.commit()
        before = self.custom()
        self.machine.write("/boot/l4h/l4h.conf", "old configuration")
        self.machine.fail = "set"
        with self.assertRaises(installer.Incompatible):
            self.commit()
        self.assertEqual(self.machine.path("/boot/l4h/l4h.conf").read_text(), "old configuration")
        self.assertEqual(self.custom(), before)
        self.assertEqual(self.machine.grubenv["next_entry"], "l4h")

    def test_disk_full_before_grub(self):
        plan = self.check()
        with patch.object(installer.shutil, "disk_usage") as usage:
            usage.return_value.free = 0
            with self.assertRaisesRegex(installer.Incompatible, "free space on /boot"):
                self.commit(plan)
        self.assertNotIn("next_entry", self.machine.grubenv)
        self.assertFalse(self.machine.path("/var/lib/l4h").exists())

    def test_file_copy_failure_before_grub(self):
        real_copy = installer.atomic_copy
        def copy_or_fail(source, dest, mode):
            if dest.name == "initrd":
                raise OSError("disk full")
            real_copy(source, dest, mode)
        with patch.object(installer, "atomic_copy", side_effect=copy_or_fail):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.commit()
        self.assertNotIn("next_entry", self.machine.grubenv)
        self.assertFalse(self.machine.path("/boot/l4h").exists())
        self.assertFalse(self.machine.path("/boot/grub/custom.cfg").exists())

    def test_changed_grub_env_before_commit(self):
        plan = self.check()
        self.machine.grubenv["next_entry"] = "1"
        with self.assertRaisesRegex(installer.Incompatible, "changed during"):
            self.commit(plan)
        self.assertFalse(self.machine.path("/boot/l4h").exists())

    def test_bad_download_checksum(self):
        self.args.release = "vtest"
        self.args.checksums = self.root / "SHA256SUMS"
        self.args.checksums.write_text("0" * 64 + "  l4h-bios-x86_64.tar.xz\n")
        with patch.object(installer, "run", return_value=""):
            with self.assertRaisesRegex(installer.Incompatible, "checksum mismatch"):
                (self.root / "l4h-bios-x86_64.tar.xz").write_text("corrupt")
                installer.download_bios(self.args, self.check(), self.root)

    def test_bios_package_unpacking(self):
        bios = self.bios_package()
        for kind in ("good", "traversal", "symlink", "no-kernel", "no-multiboot"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                work = Path(temp)
                archive = work / "l4h-bios-x86_64.tar.xz"
                with tarfile.open(archive, "w:xz") as tar:
                    for file in sorted(bios.iterdir()):
                        if kind == "no-kernel" and file.name == "kernel-generic.elf":
                            continue
                        data = elf() if kind == "no-multiboot" and file.name.startswith("kernel-") else file.read_bytes()
                        info = tarfile.TarInfo("l4h-bios-x86_64/" + file.name)
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                    if kind in ("traversal", "symlink"):
                        info = tarfile.TarInfo("l4h-bios-x86_64/../escape" if kind == "traversal" else "l4h-bios-x86_64/link")
                        if kind == "symlink":
                            info.type = tarfile.SYMTYPE
                            info.linkname = "/etc/passwd"
                        tar.addfile(info, io.BytesIO(b""))
                if kind == "good":
                    out = installer.unpack_bios(archive, work, "generic")
                    self.assertEqual((out / "vmlinux").read_bytes(), elf())
                else:
                    with self.assertRaisesRegex(installer.Incompatible, "unsafe|lacks|multiboot2"):
                        installer.unpack_bios(archive, work, "generic")
                    self.assertFalse((work / "escape").exists())


if __name__ == "__main__":
    unittest.main(buffer=True)
