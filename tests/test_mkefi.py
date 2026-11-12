#!/usr/bin/env python3
"""Exercise mkefi's generated configuration without building an EFI image."""
import os
from pathlib import Path
import shutil
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
                   L4H_GUEST_KMODS="", L4H_MKSHIM="", **settings)
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

    def test_literals_are_escaped_for_grub(self):
        self.assertEqual(self.generate(L4H_ESP_LABEL='slot "$name"\\end').returncode, 0)
        self.assertIn(r'--label -- "slot \"\$name\"\\end"', self.config.read_text())

    def test_invalid_build_settings_fail(self):
        for settings in [dict(L4H_ESP_UUID="a", L4H_ESP_LABEL="b"),
                         dict(L4H_BOOT_ENV="/grubenv"),
                         dict(L4H_ESP_LABEL="boot", L4H_BOOT_ENV="relative"),
                         dict(L4H_ESP_LABEL="boot", L4H_BOOT_ENV="(hd0)/grubenv"),
                         dict(L4H_ESP_LABEL="boot\nother"),
                         dict(L4H_ESP_UUID="a", L4H_BOOT_ENV="/grub\nenv")]:
            with self.subTest(settings=settings):
                self.assertNotEqual(self.generate(**settings).returncode, 0)


if __name__ == "__main__":
    unittest.main()
