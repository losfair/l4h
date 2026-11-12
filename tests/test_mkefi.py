#!/usr/bin/env python3
"""Exercise mkefi's configuration and EFI wrapper without a full host build."""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MkefiTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        grub = self.work / "grub-mkstandalone"
        grub.write_text("""#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
for arg in args:
    if arg.startswith('boot/grub/grub.cfg='):
        shutil.copyfile(arg.split('=', 1)[1], os.environ['TEST_GRUB_CONFIG'])
pathlib.Path(os.environ['TEST_GRUB_MODULES']).write_text(next(a for a in args if a.startswith('--modules=')))
pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'EFI fixture')
""")
        grub.chmod(0o755)
        self.config = self.work / "grub.cfg"
        self.modules = self.work / "modules"

    def generate(self, **settings):
        env = {k: v for k, v in os.environ.items() if not k.startswith("L4H_")}
        env.update(PATH=f"{self.work}:{env['PATH']}", TEST_GRUB_CONFIG=str(self.config),
                   TEST_GRUB_MODULES=str(self.modules), L4H_GUEST_KERNEL="/bin/true",
                   L4H_GUEST_KMODS="", L4H_MKSHIM="")
        env.update(settings)
        result = subprocess.run([str(ROOT / "tools/mkefi.sh"), str(self.work / "out.efi"),
                                 "/bin/true", "/bin/true"], env=env, capture_output=True, text=True)
        if result.returncode == 0 and shutil.which("grub-script-check"):
            subprocess.run(["grub-script-check", str(self.config)], check=True)
        return result

    def test_default_keeps_loaded_partition_and_file_search(self):
        self.assertEqual(self.generate().returncode, 0)
        config = self.config.read_text()
        self.assertIn('"$cmdpath"', config)
        self.assertIn('--file /l4h/dom0/initrd', config)
        self.assertNotIn('l4h_esp_uuid=', config)
        self.assertNotIn('/boot/mk/', config)
        self.assertNotIn('\ntrue\n', config)

    def test_uuid_and_label_select_before_sourcing_any_config(self):
        for key, flag, value in [("L4H_ESP_UUID", "--fs-uuid", "1234-ABCD"),
                                 ("L4H_ESP_LABEL", "--label", "slot A")]:
            with self.subTest(key=key):
                self.assertEqual(self.generate(**{key: value}).returncode, 0)
                config = self.config.read_text()
                self.assertIn(f'{flag} -- "{value}"', config)
                self.assertNotIn('--file /l4h/dom0/initrd', config)
                self.assertLess(config.index('if [ "$l4h_boot_ok" = 1 ]'), config.index('source '))

    def test_environment_import_is_whitelisted_and_precedes_slot_files(self):
        self.assertEqual(self.generate(L4H_ESP_UUID="1234-ABCD", L4H_BOOT_ENV="/EFI/L4H/grubenv").returncode, 0)
        config = self.config.read_text()
        self.assertIn('load_env --file "($esp)/EFI/L4H/grubenv" l4h_esp_uuid l4h_esp_label', config)
        self.assertLess(config.index('load_env --file "($esp)'), config.index('source '))
        self.assertIn('l4h: boot partition selection failed', config)
        self.assertIn('search_fs_uuid search_label', self.modules.read_text())
        self.assertIn('\n    exit\n', config)
        self.assertNotIn('halt', self.modules.read_text())

    def test_literals_are_escaped_for_grub(self):
        self.assertEqual(self.generate(L4H_ESP_LABEL='slot "$name"\\end').returncode, 0)
        self.assertIn(r'--label -- "slot \"\$name\"\\end"', self.config.read_text())

    def test_backticks_are_literals_in_grub_labels_and_paths(self):
        self.assertEqual(self.generate(L4H_ESP_LABEL='slot`A', L4H_BOOT_ENV='/EFI/grub`env').returncode, 0)
        config = self.config.read_text()
        self.assertIn('--label -- "slot`A"', config)
        self.assertIn('load_env --file "($esp)/EFI/grub`env"', config)

    def test_multikernel_block_is_emitted_only_when_available(self):
        shim = self.work / 'mkshim'
        shim.mkdir()
        (shim / 'l4h-mkshim.elf').touch()
        self.assertEqual(self.generate(L4H_MKSHIM=str(shim)).returncode, 0)
        config = self.config.read_text()
        self.assertIn('if [ -n "$esp" ]; then\nif [ -f "($esp)/l4h/l4h-mk.conf" ]; then', config)
        self.assertIn('(memdisk)/boot/mk/l4h-mkshim.elf', config)
        self.assertNotIn('\ntrue\n', config)

    def test_invalid_build_settings_fail(self):
        for settings in [dict(L4H_ESP_UUID="a", L4H_ESP_LABEL="b"),
                         dict(L4H_BOOT_ENV="/grubenv"),
                         dict(L4H_ESP_LABEL="boot", L4H_BOOT_ENV="relative"),
                         dict(L4H_ESP_LABEL="boot", L4H_BOOT_ENV="(hd0)/grubenv"),
                         dict(L4H_ESP_LABEL="boot\nother"),
                         dict(L4H_ESP_UUID="a", L4H_BOOT_ENV="/grub\nenv")]:
            with self.subTest(settings=settings):
                self.assertNotEqual(self.generate(**settings).returncode, 0)

    def test_wrapper_status_device_path_and_cleanup(self):
        binary = self.work / "efi-wrapper-test"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-mno-red-zone",
                        str(ROOT / "tests/efi-wrapper.c"), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)

    def test_wrapper_is_a_relocatable_efi_application(self):
        self.assertEqual(self.generate().returncode, 0)
        image = (self.work / 'out.efi').read_bytes()
        self.assertEqual(image[:2], b'MZ')
        pe, = struct.unpack_from('<I', image, 0x3c)
        self.assertEqual(image[pe:pe + 4], b'PE\0\0')
        machine, sections = struct.unpack_from('<HH', image, pe + 4)
        self.assertEqual(machine, 0x8664)
        optional_size, = struct.unpack_from('<H', image, pe + 20)
        optional = pe + 24
        self.assertEqual(struct.unpack_from('<H', image, optional)[0], 0x20b)
        self.assertEqual(struct.unpack_from('<H', image, optional + 68)[0], 10)
        entry, = struct.unpack_from('<I', image, optional + 16)
        headers, = struct.unpack_from('<I', image, optional + 60)
        reloc, reloc_size = struct.unpack_from('<II', image, optional + 152)
        self.assertGreater(reloc_size, 0)
        executable_entry = relocation_section = False
        for i in range(sections):
            name, size, addr, raw_size, raw, _, _, _, _, flags = struct.unpack_from(
                '<8sIIIIIIHHI', image, optional + optional_size + i * 40)
            # OVMF rejects sections at RVA 0 overlapping the PE headers,
            # including a compiler's non-loadable .comment section.
            self.assertGreaterEqual(addr, headers, name)
            if raw_size:
                self.assertGreaterEqual(raw, headers, name)
                self.assertLessEqual(raw + raw_size, len(image), name)
            executable_entry |= addr <= entry < addr + size and bool(flags & 0x20000000)
            relocation_section |= addr <= reloc and reloc + reloc_size <= addr + size
        self.assertTrue(executable_entry)
        self.assertTrue(relocation_section)


if __name__ == "__main__":
    unittest.main()
