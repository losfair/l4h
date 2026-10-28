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
                   " ".join(installer.CPU_FLAGS | {"arch_capabilities", "pcid", "invpcid", "x2apic"}))
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

    def pci(self, bdf, vendor, device, cls, msix=True, modern=True, io_bar=False):
        base = "/sys/devices/pci0000:00/0000:" + bdf
        for name, value in (("vendor", vendor), ("device", device), ("class", cls)):
            self.write(base + "/" + name, hex(value))
        config = bytearray(256)
        config[0x34] = 0x40
        config[0x40:0x44] = bytes([0x11 if msix else 1, 0x50, 3, 0])
        config[0x50:0x54] = bytes([9 if modern else 1, 0, 16, 1])
        self.write(base + "/config", config)
        bars = "0x1000 0x5fff 0x200\n" * 6
        if io_bar:  # A legacy virtio device's registers in I/O BAR 0.
            bars = "0xc000 0xc03f 0x101\n" + bars.split("\n", 1)[1]
        self.write(base + "/resource", bars)

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
        if args == ("/usr/local/bin/l4hctl", "info"):
            return "cores:  4\nmemory: 4096 MiB free of 7936 MiB\ndisks: 1\nvms: 1"
        if args[0] == "efibootmgr":
            if args[1] == "--verbose":
                text = "BootOrder: {}\nBootCurrent: {}\n".format(self.boot["order"], self.boot["current"])
                if self.boot["next"]:
                    text += "BootNext: " + self.boot["next"] + "\n"
                return text + "\n".join("Boot{}{} {}".format(n, "" if n in self.boot.get("inactive", []) else "*", v)
                                        for n, v in self.boot["entries"].items())
            if "--create-only" in args:
                self.boot["entries"][args[args.index("--bootnum") + 1]] = (
                    "L4H\tHD(1,GPT,aabbccdd-0011-2233-4455-66778899aabb,0x800,0x80000)/File(" + installer.LOADER + ")")
            elif "--delete-bootnum" in args:
                self.boot["entries"].pop(args[args.index("--bootnum") + 1], None)
            elif "--active" in args:
                self.boot["inactive"].remove(args[args.index("--bootnum") + 1])
            elif "--inactive" in args:
                self.boot["inactive"].append(args[args.index("--bootnum") + 1])
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

    def dom0(self):
        shutil.rmtree(self.path("/sys/firmware"))
        shutil.rmtree(self.path("/sys/devices/pci0000:00"))
        self.path("/sys/kernel/l4h").mkdir(parents=True)
        self.write("/sys/class/misc/l4hctl/dev", "10:127")
        self.write("/proc/cpuinfo", "processor: 0\nvendor_id: l4h\nflags: fpu")
        self.write("/proc/meminfo", "MemTotal: 524288 kB")
        self.write("/proc/cmdline", "console=hvc0 root=UUID=1234-abcd ro")
        # Passthrough keeps UUIDs but exposes different block names in dom0.
        names = {"/dev/vda": "/dev/l4hblk0", "/dev/vda1": "/dev/l4hblk0p1", "/dev/vda2": "/dev/l4hblk0p2"}
        for old, new in names.items():
            if self.path(old).is_file():
                self.path(old).rename(self.path(new))
        self.write("/sys/class/block/l4hblk0p1/partition", "1")
        for block in self.blocks:
            block["name"] = names[block["name"]]
            block["pkname"] = names.get(block["pkname"])
        for mount in self.mounts:
            mount["source"] = names[mount["source"]]
        self.calls.clear()


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


class UpdateChecks:
    """The same update contract on both firmware layouts."""

    def config(self):
        state = json.loads(self.machine.path(installer.STATE).read_text())
        directory = state["esp"] + "/l4h" if state["firmware"] == "uefi" else "/boot/l4h"
        return self.machine.path(directory + "/l4h.conf")

    def test_skim_install_and_native_dom0_updates(self):
        self.machine.write("/sys/devices/system/cpu/vulnerabilities/meltdown", "Mitigation: PTI")
        self.commit()
        self.assertEqual(self.check()["variant"], "skim-xapic-nopcid")
        self.commit()
        self.args.variant = "xapic-nopcid"
        self.machine.calls.clear()
        self.rejected("requires the skim-xapic-nopcid")
        self.args.variant = None
        self.machine.dom0()
        self.assertEqual(self.check()["variant"], "skim-xapic-nopcid")
        self.commit()
        for variant in ("generic", "xapic-nopcid"):
            self.args.variant = variant
            self.rejected("requires native Linux")

    def test_dom0_can_enable_skim(self):
        self.commit()
        self.machine.dom0()
        self.args.variant = "skim-xapic-nopcid"
        self.commit()
        self.args.variant = None
        self.assertEqual(self.check()["variant"], "skim-xapic-nopcid")

    def test_native_update_preserves_config_and_variant(self):
        self.args.variant = "xapic-nopcid"
        self.commit()
        self.args.variant = None
        config = self.config()
        custom = config.read_text().replace("dom0_mem_mb=4096", "dom0_mem_mb=1536") + "# operator settings\nlog_level=debug\n"
        config.write_text(custom)
        config.chmod(0o600)
        before = config.stat()
        plan = self.check()
        self.assertTrue(plan["update"])
        self.assertFalse(plan["dom0"])
        self.assertEqual(plan["variant"], "xapic-nopcid")
        self.commit(plan)
        self.assertEqual(config.read_text(), custom)
        after = config.stat()
        self.assertEqual((after.st_mode, after.st_ino, after.st_mtime_ns),
                         (before.st_mode, before.st_ino, before.st_mtime_ns))

    def test_dom0_update_uses_installed_layout(self):
        self.commit()
        config = self.config().read_bytes()
        self.machine.dom0()
        plan = self.check()
        self.assertTrue(plan["dom0"])
        self.assertEqual(plan["variant"], "generic")
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.commit(plan)
        self.assertIn("host-reboot", output.getvalue())
        self.assertEqual(self.config().read_bytes(), config)
        self.assertFalse(any(call[0] in ("ip", "efibootmgr", "systemctl") for call in self.machine.calls))
        if plan["firmware"] == "uefi":
            self.assertIn("boot selection is unchanged", output.getvalue())
        else:
            self.assertEqual(self.machine.grubenv["next_entry"], "l4h")

    def test_dom0_resource_override_uses_host_capacity(self):
        self.commit()
        self.machine.dom0()
        self.args.memory, self.args.vcpus = 2048, 3
        expected = self.config().read_text().replace("dom0_mem_mb=4096", "dom0_mem_mb=2048").replace("dom0_vcpus=1", "dom0_vcpus=3")
        self.commit()
        self.assertEqual(self.config().read_text(), expected)
        self.args.memory = 8000
        self.rejected("dom0 RAM")

    def test_legacy_update_identifies_variant_once_and_records_it(self):
        self.commit()
        state = self.machine.path(installer.STATE)
        record = json.loads(state.read_text())
        for key in ("version", "variant", "root_uuid", "esp_partuuid", "boot_uuid"):
            record.pop(key, None)
        state.write_text(json.dumps(record))
        self.machine.dom0()
        with patch.object(installer, "installed_variant", return_value="xapic-nopcid") as identify:
            plan = self.check()
            self.assertEqual(self.check(), plan)
            self.commit(plan)
        identify.assert_called_once()
        self.assertEqual(json.loads(state.read_text())["variant"], "xapic-nopcid")

    def test_update_rejects_wrong_root_and_concurrent_config_change(self):
        self.commit()
        config = self.config()
        original = config.read_text()
        self.machine.calls.clear()
        config.write_text(original.replace("root=UUID=1234-abcd", "root=UUID=5678-abcd"))
        self.rejected("mounted root")
        config.write_text(original)
        plan = self.check()
        config.write_text(original + "# changed after preflight\n")
        with self.assertRaisesRegex(installer.Incompatible, "changed during update"):
            self.commit(plan)
        self.assertTrue(config.read_text().endswith("# changed after preflight\n"))

    def payload(self):
        state = json.loads(self.machine.path(installer.STATE).read_text())
        return self.machine.path(state["esp"] + "/EFI/L4H/l4h.efi" if state["firmware"] == "uefi" else "/boot/l4h/bios/kernel.elf")

    def test_update_restores_missing_boot_payload(self):
        self.commit()
        payload = self.payload()
        original = payload.read_bytes()
        payload.unlink()
        plan = self.check()
        # A file appearing during download must not be silently overwritten.
        payload.write_bytes(b"concurrent repair")
        with self.assertRaisesRegex(installer.Incompatible, "changed during update"):
            self.commit(plan)
        payload.unlink()
        self.commit(plan)
        self.assertEqual(payload.read_bytes(), original)

    def test_missing_legacy_payload_needs_explicit_variant(self):
        self.commit()
        self.payload().unlink()
        state = self.machine.path(installer.STATE)
        record = json.loads(state.read_text())
        record.pop("variant")
        state.write_text(json.dumps(record))
        self.machine.calls.clear()
        self.rejected("specify --variant")
        self.args.variant = "generic"
        self.commit()
        self.assertTrue(self.payload().is_file())


class InstallerTests(UpdateChecks, Harness):
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

    def test_affected_or_unknown_cpu_selects_skim(self):
        path = "/sys/devices/system/cpu/vulnerabilities/meltdown"
        for status in ("Mitigation: PTI", "Vulnerable", "Unknown", ""):
            with self.subTest(status=status):
                self.machine.write(path, status)
                self.args.variant = None
                self.assertEqual(self.check()["variant"], "skim-xapic-nopcid")
                for variant in ("generic", "xapic-nopcid"):
                    self.args.variant = variant
                    self.rejected("requires the skim-xapic-nopcid")
        self.args.variant = None
        self.machine.path(path).unlink()
        self.assertEqual(self.check()["variant"], "skim-xapic-nopcid")

    def test_intel_without_arch_capabilities_selects_skim(self):
        cpu = self.machine.path("/proc/cpuinfo")
        cpu.write_text(cpu.read_text().replace("arch_capabilities", ""))
        self.assertEqual(self.check()["variant"], "skim-xapic-nopcid")
        self.args.variant = "generic"
        self.rejected("requires the skim-xapic-nopcid")
        self.args.variant = None
        cpu.write_text(cpu.read_text().replace("GenuineIntel", "AuthenticAMD"))
        self.assertEqual(self.check()["variant"], "generic")

    def test_explicit_skim_on_unaffected_cpu(self):
        self.args.variant = "skim-xapic-nopcid"
        self.assertEqual(self.check()["variant"], "skim-xapic-nopcid")

    def test_pcid_without_invpcid_uses_fallback(self):
        cpu = self.machine.path("/proc/cpuinfo")
        cpu.write_text(cpu.read_text().replace("invpcid", ""))
        self.assertEqual(self.check()["variant"], "xapic-nopcid")
        self.args.variant = "generic"
        self.rejected("INVPCID")

    def test_missing_cpu_feature(self):
        cpu = self.machine.path("/proc/cpuinfo")
        cpu.write_text(cpu.read_text().replace("xsaveopt", ""))
        self.rejected("xsaveopt")

    def test_constant_tsc_requires_explicit_override(self):
        cpu = self.machine.path("/proc/cpuinfo")
        cpu.write_text(cpu.read_text().replace("GenuineIntel", "AuthenticAMD").replace("constant_tsc", ""))
        self.rejected("required features: constant_tsc")
        self.args = self.preflight.args = installer.arguments(["--check", "--assume-stable-tsc"])
        with patch("sys.stderr", new_callable=io.StringIO) as err:
            plan = self.check()
            self.assertEqual(self.check(), plan)
        self.assertIn("constant_tsc is not advertised", err.getvalue())
        self.assertIn("--assume-stable-tsc", err.getvalue())
        self.args.assume_stable_tsc = False
        self.rejected("required features: constant_tsc")

    def test_tsc_override_keeps_other_cpu_requirements(self):
        self.args.assume_stable_tsc = True
        cpu = self.machine.path("/proc/cpuinfo")
        original = cpu.read_text().replace("constant_tsc", "")
        for feature in ("xsaveopt", "avx", "pdpe1gb"):
            with self.subTest(feature=feature):
                cpu.write_text(original.replace(feature, ""))
                self.rejected("required features: " + feature)

    def test_tsc_override_with_advertised_constant_tsc(self):
        expected = self.check()
        self.args.assume_stable_tsc = True
        with patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(self.check(), expected)
        self.assertEqual(err.getvalue(), "")

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

    def test_default_dom0_memory(self):
        # Include the usable RAM reported by a nominal 1 GiB Vultr VM.
        for total, expected in ((768, 512), (947, 512), (1024, 512),
                                (2048, 1024), (3072, 1536), (8192, 4096),
                                (16384, 8192), (131072, 8192)):
            with self.subTest(total=total):
                self.machine.write("/proc/meminfo", f"MemTotal: {total * 1024} kB")
                plan = self.check()
                self.assertEqual(plan["memory"], expected)
                self.assertIn(f"dom0_mem_mb={expected}\n", installer.configuration(plan))

    def test_insufficient_physical_memory_even_with_swap(self):
        self.machine.write("/proc/meminfo", "MemTotal: 786431 kB\nSwapTotal: 8388608 kB")
        for memory in (None, 512):
            with self.subTest(memory=memory):
                self.args.memory = memory
                self.rejected("at least 768 MiB usable RAM.*found 767 MiB")

    def test_small_vm_memory_override_preserves_host_reserve(self):
        self.machine.write("/proc/meminfo", f"MemTotal: {947 * 1024} kB")
        for memory in (512, 513, 640, 690):
            with self.subTest(memory=memory):
                self.args.memory = memory
                self.assertEqual(self.check()["memory"], memory)
        # 691 MiB rounds up to 692 MiB in vmmgr, leaving only 255 MiB.
        for memory in (511, 691, 692, 947):
            with self.subTest(memory=memory):
                self.args.memory = memory
                self.rejected("dom0 RAM must be 512..690 MiB.*reserving 256 MiB")

    def test_maximum_dom0_memory(self):
        self.machine.write("/proc/meminfo", f"MemTotal: {131072 * 1024} kB")
        self.args.memory = 61440
        self.assertEqual(self.check()["memory"], 61440)
        self.args.memory = 61441
        self.rejected("dom0 RAM must be 512..61440 MiB")

    def test_lvm_and_unsupported_fs(self):
        self.machine.blocks[2]["type"] = "lvm"
        self.rejected("plain disks")
        self.machine.blocks[2]["type"] = "part"
        for fstype in ("ext2", "ext3", "btrfs"):
            with self.subTest(fstype=fstype):
                self.machine.mounts[0]["fstype"] = fstype
                self.rejected("ext4 or XFS")

    def test_sata_and_legacy_virtio(self):
        self.machine.pci("00:04.0", 0x8086, 0x2922, 0x010601)
        self.rejected("SATA")
        # Legacy (0.9.5) virtio-blk and virtio-scsi: registers in I/O BAR 0.
        for device in (0x1001, 0x1004):
            with self.subTest(device=hex(device)):
                self.machine.pci("00:04.0", 0x1AF4, device, 0x010000, modern=False, io_bar=True)
                self.check()
                self.machine.pci("00:04.0", 0x1AF4, device, 0x010000, modern=False)
                self.rejected("NVMe, virtio-blk or virtio-scsi")
        # A modern-only device ID has no legacy interface.
        self.machine.pci("00:04.0", 0x1AF4, 0x1042, 0x010000, modern=False, io_bar=True)
        self.rejected("NVMe, virtio-blk or virtio-scsi")

    def test_legacy_virtio_net(self):
        self.machine.pci("00:05.0", 0x1AF4, 0x1000, 0x020000, modern=False, io_bar=True)
        self.check()
        self.machine.pci("00:05.0", 0x1AF4, 0x1000, 0x020000, modern=False)
        self.rejected("supported uplinks")

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

    def test_unsupported_network_and_enslaved_physical_nic(self):
        self.machine.pci("00:05.0", 0x8086, 0x100E, 0x020000)
        self.rejected("supported uplinks")
        self.machine.pci("00:05.0", 0x1AF4, 0x1041, 0x020000)
        self.machine.links.append(dict(ifname="br0", link_type="ether", linkinfo=dict(info_kind="bridge")))
        self.machine.links[1]["master"] = "br0"
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

    def test_virtual_interfaces_do_not_change_uplink_plan(self):
        virtual = [
            dict(ifname="wg-obfs", link_type="none", linkinfo=dict(info_kind="wireguard")),
            dict(ifname="ppp0", link_type="ppp"),
            dict(ifname="gre0", link_type="gre"),
            dict(ifname="tun0", link_type="none"),
            dict(ifname="tap0", link_type="ether"),
            dict(ifname="br0", link_type="ether", linkinfo=dict(info_kind="bridge")),
            dict(ifname="bond0", link_type="ether", linkinfo=dict(info_kind="bond")),
            dict(ifname="ens3.10", link_type="ether", linkinfo=dict(info_kind="vlan")),
            dict(ifname="veth0", link_type="ether", master="br0"),
            dict(ifname="unknown0", link_type="ether", linkinfo=dict(info_kind="unknown")),
        ]
        # These links exist in sysfs, but have no backing hardware device.
        for link in virtual:
            self.machine.path("/sys/class/net/" + link["ifname"]).mkdir()
        for nics in (1, 2):
            with self.subTest(nics=nics):
                if nics == 2:
                    self.machine.nic("ens4", "00:06.0", "52:54:00:12:34:57")
                expected = self.check()
                self.machine.links.extend(virtual)
                self.assertEqual(self.check(), expected)
                self.assertEqual(installer.configuration(self.check()), installer.configuration(expected))
                del self.machine.links[-len(virtual):]

    def test_virtual_interfaces_do_not_replace_a_physical_uplink(self):
        self.machine.links = [self.machine.links[0],
                              dict(ifname="tap0", link_type="ether"),
                              dict(ifname="wg-obfs", link_type="none", linkinfo=dict(info_kind="wireguard"))]
        self.rejected("one or two physical NICs")

    def test_virtual_interfaces_do_not_bypass_uplink_checks(self):
        self.machine.links.append(dict(ifname="wg-obfs", link_type="none", linkinfo=dict(info_kind="wireguard")))
        self.machine.pci("00:05.0", 0x8086, 0x100E, 0x020000)
        self.rejected("ens3: supported uplinks")
        self.machine.pci("00:05.0", 0x1AF4, 0x1041, 0x020000)
        self.machine.links[1]["master"] = "br0"
        self.rejected("ens3: need a plain Ethernet")
        del self.machine.links[1]["master"]
        self.machine.write("/sys/class/net/ens3/addr_assign_type", "3")
        self.rejected("ens3: uplink MAC has been changed")

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

    def test_update_recreates_missing_efi_entry(self):
        self.commit()
        # The old installer recorded only these three fields. The firmware
        # entry disappeared after the trial, but the deployment is intact.
        state = self.machine.path(installer.STATE)
        state.write_text(json.dumps(dict(esp="/boot/efi", entry="0008", release="vtest")))
        self.machine.boot["entries"].pop("0000")
        self.machine.boot["next"] = None
        original = copy.deepcopy(self.machine.boot)
        config = self.machine.path("/boot/efi/l4h/l4h.conf").read_bytes()
        with patch.object(installer, "installed_variant", return_value="generic"):
            plan = self.check()
        self.assertIsNone(plan["entry"])
        self.assertEqual(self.machine.boot, original)  # --check does not repair NVRAM.
        self.commit(plan)
        record = json.loads(state.read_text())
        self.assertEqual(record["entry"], "0008")
        self.assertTrue(installer.owns_entry(installer.boot_state(self.machine.command("efibootmgr", "--verbose")), record["entry"], plan))
        self.assertEqual(self.machine.boot["order"], original["order"])
        self.assertEqual(self.machine.boot["next"], record["entry"])
        self.assertEqual(self.config().read_bytes(), config)

    def test_update_reuses_renumbered_efi_entry(self):
        self.commit()
        self.machine.boot["entries"]["0008"] = self.machine.boot["entries"].pop("0000")
        self.machine.boot["entries"]["0000"] = "Other OS\tHD(other)"
        self.machine.boot["next"] = "0008"
        self.machine.calls.clear()
        self.commit()
        self.assertEqual(json.loads(self.machine.path(installer.STATE).read_text())["entry"], "0008")
        self.assertEqual(self.machine.boot["entries"]["0000"], "Other OS\tHD(other)")
        self.assertFalse(any("--create-only" in call for call in self.machine.calls))

    def test_recreated_entry_does_not_overwrite_reused_number(self):
        self.commit()
        self.machine.boot["entries"]["0000"] = "Other OS\tHD(other)"
        self.machine.boot["next"] = None
        self.commit()
        entry = json.loads(self.machine.path(installer.STATE).read_text())["entry"]
        self.assertNotEqual(entry, "0000")
        self.assertEqual(self.machine.boot["entries"]["0000"], "Other OS\tHD(other)")
        self.assertEqual(self.machine.boot["next"], entry)

    def test_missing_entry_repair_rolls_back_on_firmware_failure(self):
        self.commit()
        self.machine.boot["entries"].pop("0000")
        # A dangling BootNext for the recorded entry is also ours to repair.
        original = copy.deepcopy(self.machine.boot)
        state = self.machine.path(installer.STATE).read_bytes()
        payload = self.machine.path("/boot/efi/EFI/L4H/l4h.efi")
        payload.write_bytes(b"previous EFI payload")
        self.machine.fail = "--bootnext"
        with self.assertRaisesRegex(installer.Incompatible, "injected"):
            self.commit()
        self.assertEqual(self.machine.boot, original)
        self.assertEqual(self.machine.path(installer.STATE).read_bytes(), state)
        self.assertEqual(payload.read_bytes(), b"previous EFI payload")
        self.commit()
        self.assertIn(self.machine.boot["next"], self.machine.boot["entries"])

    def test_missing_entry_repair_preserves_foreign_bootnext(self):
        self.commit()
        self.machine.boot["entries"]["0000"] = "Other OS\tHD(other)"
        self.machine.calls.clear()
        self.commit()
        self.assertEqual(self.machine.boot["next"], "0000")
        self.assertEqual(self.machine.boot["entries"]["0000"], "Other OS\tHD(other)")
        self.assertFalse(any("--bootnext" in call for call in self.machine.calls))

    def test_update_keeps_entry_for_another_esp(self):
        self.commit()
        self.machine.calls.clear()
        self.machine.boot["entries"]["0000"] = self.machine.boot["entries"]["0000"].replace("HD(1,", "HD(2,")
        other = self.machine.boot["entries"]["0000"]
        self.machine.boot["next"] = None
        self.commit()
        self.assertEqual(self.machine.boot["entries"]["0000"], other)
        entry = json.loads(self.machine.path(installer.STATE).read_text())["entry"]
        self.assertNotEqual(entry, "0000")
        self.assertEqual(self.machine.boot["next"], entry)

    def test_update_rejects_changed_esp_identity(self):
        self.commit()
        self.machine.calls.clear()
        self.machine.blocks[1]["partuuid"] = "bbbbbbbb-0011-2233-4455-66778899aabb"
        self.rejected("different ESP")

    def test_update_does_not_reuse_backup_loader(self):
        self.commit()
        other = self.machine.boot["entries"]["0000"].replace("l4h.efi", "l4h.efi.backup")
        self.machine.boot["entries"]["0000"] = other
        self.machine.boot["next"] = None
        self.commit()
        self.assertEqual(self.machine.boot["entries"]["0000"], other)
        self.assertNotEqual(self.machine.boot["next"], "0000")

    def test_update_reuses_matching_duplicate_efi_entry(self):
        self.commit()
        self.machine.boot["entries"]["0008"] = self.machine.boot["entries"]["0000"]
        self.machine.boot["entries"]["0009"] = self.machine.boot["entries"]["0000"].replace("HD(1,", "HD(2,")
        self.machine.calls.clear()
        self.commit()
        self.assertEqual(json.loads(self.machine.path(installer.STATE).read_text())["entry"], "0000")
        self.machine.boot["entries"].pop("0000")
        self.commit()
        self.assertEqual(json.loads(self.machine.path(installer.STATE).read_text())["entry"], "0008")
        self.assertEqual(self.machine.boot["next"], "0008")
        self.assertFalse(any("--create-only" in call or "--delete-bootnum" in call for call in self.machine.calls))

    def test_update_reactivates_efi_entry_and_undoes_it_on_failure(self):
        self.commit()
        self.machine.boot["inactive"] = ["0000"]
        self.machine.fail = "--bootnext"
        with self.assertRaisesRegex(installer.Incompatible, "injected"):
            self.commit()
        self.assertEqual(self.machine.boot["inactive"], ["0000"])
        self.commit()
        self.assertEqual(self.machine.boot["inactive"], [])

    def test_update_preserves_scheduled_native_boot(self):
        self.commit()
        self.machine.boot["next"] = "0002"
        self.commit()
        self.assertEqual(self.machine.boot["next"], "0002")
        self.assertEqual(self.machine.boot["order"], "0001,0002")
        self.commit(default=True)
        self.assertEqual(self.machine.boot["next"], "0002")
        self.assertEqual(self.machine.boot["order"], "0000,0001,0002")

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
        config = self.config().read_text() + "# custom configuration\n"
        self.config().write_text(config)
        payload = self.machine.path("/boot/efi/EFI/L4H/l4h.efi")
        payload.write_bytes(b"previous EFI payload")
        self.args.memory = 2048
        self.machine.fail = "--bootnext"
        with self.assertRaisesRegex(installer.Incompatible, "injected"):
            self.commit()
        self.assertEqual(self.config().read_text(), config)
        self.assertEqual(payload.read_bytes(), b"previous EFI payload")
        self.assertEqual(self.machine.boot, original)

    def test_uefi_dom0_cannot_change_firmware_default(self):
        self.commit()
        self.machine.dom0()
        self.args.make_default = True
        self.rejected("boot order changes require native Linux")

    def test_legacy_efi_variant_matches_release_checksum(self):
        self.package()
        checksum = installer.digest(self.root / "new.efi")
        for variant in installer.KERNEL_VARIANTS:
            with self.subTest(variant=variant):
                def download(*args):
                    Path(args[args.index("--output") + 1]).write_text(checksum + "  l4h-" + variant + ".efi\n")
                with patch.object(installer, "run", side_effect=download):
                    self.assertEqual(installer.installed_variant("vold", "uefi", checksum), variant)
                    with self.assertRaisesRegex(installer.Incompatible, "specify --variant"):
                        installer.installed_variant("vold", "uefi", "0" * 64)

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
        for args in (["--help"], ["--assume-stable-tsc", "--help"]):
            with self.subTest(args=args):
                result = subprocess.run(["bash", "-s", "--", *args], input=script, capture_output=True)
                self.assertEqual(result.returncode, 0)
                self.assertIn(b"BootNext", result.stdout)
                self.assertIn(b"--assume-stable-tsc", result.stdout)
        result = subprocess.run(["bash", "-s", "--", "--unknown"], input=script, capture_output=True)
        self.assertEqual(result.returncode, 2)


def elf(multiboot2=False):
    header = bytearray(4096)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 18, 0x3E)
    if multiboot2:
        struct.pack_into("<I", header, 0x1000 - 32, 0xE85250D6)
    return bytes(header)


class BiosInstallerTests(UpdateChecks, Harness):
    def setUp(self):
        super().setUp()
        self.machine.bios()

    def bios_package(self):
        bios = self.root / "bios"
        for name in ("grub.cfg", "kmods.erofs"):
            self.machine.write("/bios/" + name, "release " + name)
        for name in ("l4h-root.elf", "vmlinux"):
            self.machine.write("/bios/" + name, elf())
        for variant in installer.KERNEL_VARIANTS:
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
        for fstype, module in (("ext2", "ext2"), ("ext3", "ext2"), ("ext4", "ext2"), ("xfs", "xfs")):
            with self.subTest(fstype=fstype):
                for table in (self.machine.blocks, self.machine.mounts, self.machine.fstab):
                    table[-1]["fstype"] = fstype
                plan = self.check()
                self.assertEqual((plan["boot_uuid"], plan["boot_fstype"], plan["grub_dir"]), ("5678-boot", fstype, "/l4h"))
                entry = installer.grub_entry(plan, False)
                self.assertIn("insmod {}\n".format(module), entry)
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
        self.assertEqual(state, dict(version=2, firmware="bios", grubdir="/boot/grub", default=False,
                                     release="vtest", variant="generic", root_uuid="1234-abcd", boot_uuid="1234-abcd"))
        self.assertFalse(any(c[0] in ("efibootmgr", "reboot", "grub-install", "update-grub", "grub-mkconfig")
                             for c in self.machine.calls))

    def test_rerun_after_a_trial_boot(self):
        self.commit()
        # GRUB's 00_header consumes next_entry with save_env, leaving it empty.
        self.machine.grubenv["next_entry"] = ""
        self.commit(default=True)
        self.assertIn("set default=l4h", self.custom())
        self.assertEqual(self.machine.grubenv["next_entry"], "")
        self.machine.grubenv["next_entry"] = "1"
        self.commit()
        self.assertEqual(self.machine.grubenv["next_entry"], "1")

    def test_update_preserves_scheduled_native_boot(self):
        self.commit()
        self.machine.grubenv["next_entry"] = "0"
        self.commit()
        self.assertEqual(self.machine.grubenv["next_entry"], "0")

    def test_update_restores_missing_generated_grub_entry(self):
        self.commit()
        custom = self.machine.path("/boot/grub/custom.cfg")
        original = custom.read_bytes()
        custom.unlink()
        self.machine.fail = "set"
        with self.assertRaisesRegex(installer.Incompatible, "injected"):
            self.commit()
        self.assertFalse(custom.exists())
        self.commit()
        self.assertEqual(custom.read_bytes(), original)

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
        config = self.config().read_text() + "# custom configuration\n"
        self.config().write_text(config)
        payload = self.machine.path("/boot/l4h/bios/kernel.elf")
        payload.write_bytes(b"previous BIOS kernel")
        self.args.memory = 2048
        self.machine.fail = "set"
        with self.assertRaisesRegex(installer.Incompatible, "injected"):
            self.commit()
        self.assertEqual(self.config().read_text(), config)
        self.assertEqual(payload.read_bytes(), b"previous BIOS kernel")
        self.assertEqual(self.custom(), before)
        self.assertEqual(self.machine.grubenv["next_entry"], "l4h")

    def test_update_preserves_custom_grub_content(self):
        self.commit()
        custom = self.machine.path("/boot/grub/custom.cfg")
        text = custom.read_text() + "# operator addition\nset timeout=7\n"
        custom.write_text(text)
        self.commit()
        self.assertEqual(custom.read_text(), text)
        self.commit(default=True)
        self.assertTrue(custom.read_text().startswith(text))
        self.assertIn("set default=l4h", custom.read_text())

    def test_legacy_bios_variant_matches_verified_archive(self):
        bios = self.bios_package()
        archive = self.root / "old.tar.xz"
        with tarfile.open(archive, "w:xz") as tar:
            tar.add(bios, arcname=installer.BIOS_PACKAGE)
        def download(*args):
            dest = Path(args[args.index("--output") + 1])
            if dest.name == "SHA256SUMS":
                dest.write_text(installer.digest(archive) + "  " + installer.BIOS_PACKAGE + ".tar.xz\n")
            else:
                shutil.copyfile(archive, dest)
        with patch.object(installer, "run", side_effect=download):
            for variant in installer.KERNEL_VARIANTS:
                with self.subTest(variant=variant):
                    checksum = installer.digest(bios / ("kernel-" + variant + ".elf"))
                    self.assertEqual(installer.installed_variant("vold", "bios", checksum), variant)

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
