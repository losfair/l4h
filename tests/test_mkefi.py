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
                   L4H_GUEST_SDK="", L4H_MKSHIM="")
        env.update(settings)
        result = subprocess.run([str(ROOT / "tools/mkefi.sh"), str(self.work / "out.efi"),
                                 "/bin/true", "/bin/true"], env=env, capture_output=True, text=True)
        if result.returncode == 0 and shutil.which("grub-script-check"):
            subprocess.run(["grub-script-check", str(self.config)], check=True)
        return result

    def test_default_discovers_selector_before_legacy_fallback(self):
        self.assertEqual(self.generate().returncode, 0)
        config = self.config.read_text()
        self.assertIn('for l4h_device in (*); do', config)
        self.assertIn('if [ -f "$l4h_device/EFI/L4H/grubenv" ]; then', config)
        self.assertIn('if [ -n "$l4h_boot_env" ]; then l4h_boot_ok=0; fi', config)
        self.assertIn('if [ -z "$l4h_boot_env" ]; then\n# Prefer', config)
        self.assertIn('"$cmdpath"', config)
        self.assertIn('--file /l4h/dom0/initrd', config)
        self.assertLess(config.index('for l4h_device'), config.index('"$cmdpath"'))
        self.check_environment_import(config)
        self.assertIn('regexp', self.modules.read_text())
        self.assertNotIn('/boot/mk/', config)
        self.assertNotIn('\ntrue\n', config)

    def check_environment_import(self, config):
        self.assertIn('load_env --file "$l4h_boot_env" l4h_esp_uuid l4h_esp_label', config)
        self.assertLess(config.index('load_env --file "$l4h_boot_env"'), config.index('source '))
        self.assertIn('l4h_esp_uuid=\nl4h_esp_label=', config)
        self.assertIn('if [ -n "$l4h_esp_uuid" -a -z "$l4h_esp_label" ]; then', config)
        self.assertIn('elif [ -n "$l4h_esp_label" -a -z "$l4h_esp_uuid" ]; then', config)

    def test_environment_import_is_whitelisted_and_precedes_slot_files(self):
        self.assertEqual(self.generate().returncode, 0)
        config = self.config.read_text()
        self.check_environment_import(config)
        self.assertIn('l4h: boot partition selection failed', config)
        self.assertIn('search_fs_uuid search_label', self.modules.read_text())
        self.assertIn('\n    exit\n', config)
        self.assertNotIn('halt', self.modules.read_text())

    def test_multikernel_block_is_emitted_only_when_available(self):
        shim = self.work / 'mkshim'
        shim.mkdir()
        (shim / 'l4h-mkshim.elf').touch()
        self.assertEqual(self.generate(L4H_MKSHIM=str(shim)).returncode, 0)
        config = self.config.read_text()
        self.assertIn('if [ -n "$esp" ]; then\nif [ -f "($esp)/l4h/l4h-mk.conf" ]; then', config)
        self.assertIn('(memdisk)/boot/mk/l4h-mkshim.elf', config)
        self.assertNotIn('\ntrue\n', config)

    def test_slot_settings_cannot_redirect_or_take_input(self):
        shim = self.work / 'mkshim'
        shim.mkdir()
        (shim / 'l4h-mkshim.elf').touch()
        for settings in ({}, {'L4H_MKSHIM': str(shim)}):
            self.assertEqual(self.generate(**settings).returncode, 0)
            config = self.config.read_text()
            # No input from the serial port: nothing to type into.
            self.assertNotIn('terminal_input', config)
            # Every failed boot exits to the wrapper (EFI_LOAD_ERROR).
            lines = config.splitlines()
            fails = [i for i, l in enumerate(lines) if 'boot failed' in l]
            self.assertEqual(len(fails), 2 if settings else 1)
            for i in fails:
                self.assertEqual(lines[i + 1].strip(), 'exit', lines[i])
            # $esp is kept across sourcing the slot's l4h.conf.
            src = config.index('source "($esp)/l4h/l4h.conf"')
            self.assertLess(config.rindex('l4h_selected_esp="$esp"', 0, src), src)
            self.assertIn('esp="$l4h_selected_esp"', config[src:src + 200])
            # serial_port is a number before anything uses it.
            check = config.index("if regexp '^(0x[0-9a-fA-F]+|[0-9]+)$' \"$serial_port\"; then true; "
                                 "else serial_port=0x3f8; fi")
            self.assertLess(src, check)
            self.assertLess(check, config.index('serial --port=$serial_port', src))
            self.assertLess(check, config.index('console_port=$serial_port'))
            self.assertIn('regexp', self.modules.read_text())
            self.assertNotIn('\ntrue\n', config)
        self.generate(L4H_SERIAL_PORT='0x2f8')
        self.assertIn('else serial_port=0x2f8; fi', self.config.read_text())

    def test_bios_config(self):
        out = self.work / 'bios'
        env = {k: v for k, v in os.environ.items() if not k.startswith("L4H_")}
        env.update(L4H_GUEST_KERNEL="/bin/true", L4H_GUEST_SDK="", L4H_MKSHIM="")
        if not shutil.which('objcopy'):
            self.skipTest('no objcopy')
        fixture = self.work / 'fixture.elf'
        subprocess.run(['cc', '-x', 'c', '-', '-o', str(fixture)], input='int main(void){return 0;}', text=True, check=True)
        env['L4H_GUEST_KERNEL'] = str(fixture)
        subprocess.run([str(ROOT / 'tools/mkbios.sh'), str(out), str(fixture), str(fixture)], env=env, check=True,
                       capture_output=True)
        config = (out / 'grub.cfg').read_text()
        if shutil.which("grub-script-check"):
            subprocess.run(["grub-script-check", str(out / 'grub.cfg')], check=True)
        self.assertNotIn('terminal_input', config)
        self.assertIn('insmod regexp', config)
        self.assertIn('echo "l4h: boot failed"\nexit\n', config)
        # FL4 boots from the same script, its kernel stripped as in its EFI.
        fl4 = self.work / 'bios-fl4'
        subprocess.run([str(ROOT / 'tools/mkbios.sh'), str(fl4), str(fixture), str(fixture)],
                       env=dict(env, L4H_KERNEL_VARIANT='fl4'), check=True, capture_output=True)
        self.assertEqual((fl4 / 'grub.cfg').read_text(), config)
        self.assertEqual((fl4 / 'kernel.elf').read_bytes(), (out / 'l4h-root.elf').read_bytes())
        self.assertFalse((fl4 / 'mk').exists())
        src = config.index('source "$l4h/l4h.conf"')
        self.assertLess(config.index('l4h_selected="$l4h"'), src)
        self.assertIn('l4h="$l4h_selected"', config[src:src + 100])
        self.assertLess(src, config.index("if regexp '^(0x[0-9a-fA-F]+|[0-9]+)$' \"$serial_port\""))
        mkimage = (ROOT / 'tools/mkimage.sh').read_text()
        core = mkimage[mkimage.index('grub-mkimage -O i386-pc'):]
        self.assertIn('regexp', core[:core.index('\n    #')])

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
