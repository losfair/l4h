#!/usr/bin/env bash
# Attestation across a chain of host kexecs (KEXEC_ATTEST_HOPS, default 4:
# more than swtpm's three loaded objects, so a host that leaves its keys in
# the TPM breaks the chain): a swtpm quote and the kexec event log verify,
# while a missing/extra key and cold-boot-only policy are rejected.
# KEXEC_ATTEST_BUILT=1 reuses the kernel, Linux and module tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/build/kexec-attest
rm -rf "$out/run" && mkdir -p "$out/run"
if [ "${KEXEC_ATTEST_BUILT:-0}" != 1 ]; then
    L4H_KERNEL_VARIANT=kexec "$root/tools/build-kernel.sh" >"$out/kernel-build.log" 2>&1
    "$root/tools/build-linux.sh" vmlinux >"$out/linux-build.log" 2>&1
    "$root/tools/build-kmods.sh" >/dev/null
fi
export SEL4_PREFIX="$root/build/sel4-kexec"
L4H_VERSION=kexec-test-1 "$root/tools/build-host.sh" >"$out/host-build-1.log" 2>&1
"$root/tools/mkefi.sh" "$out/cold.efi" \
    "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" \
    "$root/build/sel4-kexec/bin/kernel.elf" "$root/build/kernel-kexec" >"$out/efi-build-1.log"
L4H_VERSION=kexec-test-2 "$root/tools/build-host.sh" >"$out/host-build-2.log" 2>&1
"$root/tools/mkefi.sh" "$out/next.efi" \
    "$root/host/target/x86_64-sel4-roottask/debug/l4h-root.elf" \
    "$root/build/sel4-kexec/bin/kernel.elf" "$root/build/kernel-kexec" >"$out/efi-build-2.log"
objcopy --strip-debug "$root/build/linux-l4h/vmlinux" "$out/run/vmlinux"
(cd "$root/tools/l4hctl" && cargo +stable build -q --release)
nonce=$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
"$root/tools/mkinitramfs.sh" "$out/run/initrd" "$root/tests/guest/init-kexec-attest" \
    "$root/tools/l4hctl/target/release/l4hctl" "$root/tests/guest/init-attest" >/dev/null
hops=${KEXEC_ATTEST_HOPS:-4}
esp_files="/l4h/next.efi=$out/next.efi"
for i in $(seq 0 "$hops"); do
    if [ "$i" = "$hops" ]; then step=kexec_done; else step=kexec_next=$((i + 1)); fi
    printf 'dom0_disks=1\ndom0_cmdline="console=hvc0 attest_nonce=%s %s"\n' "$nonce" "$step" >"$out/kexec$i.conf"
    [ "$i" = 0 ] || esp_files="$esp_files /l4h/kexec$i.conf=$out/kexec$i.conf"
done
L4H_ESP_FILES="$esp_files" \
    "$root/tools/mkimage.sh" -e "$out/cold.efi" -i "$out/run/initrd" -c "$out/kexec0.conf" "$out/run/l4h.raw" >"$out/image-build.log"
attest=$root/tools/l4h-attest.py
rm -rf "$out/tpm"
"$root/tools/swtpm.sh" "$out/tpm"
log=$out/qemu.log
timeout "${KEXEC_ATTEST_TIMEOUT:-$((120 + 60 * hops))}" "$root/tools/run-uefi.sh" "$out/run/l4h.raw" \
    -chardev socket,id=tpm,path="$out/tpm/sock" -tpmdev emulator,id=tpm0,chardev=tpm \
    -device tpm-crb,tpmdev=tpm0 </dev/null >"$log" 2>&1 &
qemu=$!
while kill -0 "$qemu" 2>/dev/null; do
    grep -aq "ATTEST: done\|KEXECATTEST: FAIL" "$log" && { sleep 1; kill "$qemu" 2>/dev/null || true; break; }
    sleep 1
done
wait "$qemu" 2>/dev/null || true
grep -aE "ATTEST|kexec|panic|Boot failed" "$log" | cut -c1-180 || true
grep -aq "ATTEST: done" "$log"
! grep -aq "KEXECATTEST: FAIL\|panic" "$log"
field() {
    sed -E 's/^\[vm[0-9]+\] //' "$1" | grep -a "^$2 [0-9a-f]*"$'\r'"*$" | head -1 | tr -d '\r' | sed "s/^$2 //" \
        | python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))" > "$3"
    [ -s "$3" ] || { echo "no $2 in $1"; exit 1; }
}
fail() { echo "KEXECATTEST: FAIL: $*"; exit 1; }
field "$log" "ATTEST: dom0 report" "$out/run/report"
field "$log" "ATTEST: evidence" "$out/run/evidence"
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))" "$@"; }
ca=$out/tpm/ca/issuercert.pem
next_digest=$(python3 "$attest" measure-efi "$out/next.efi")
initrd_digest=$(sha256sum "$out/run/initrd" | cut -d' ' -f1)
file_policy=(--trusted-initrd "$initrd_digest")
for i in $(seq 1 "$hops"); do
    file_policy+=(--trusted-config "$(sha256sum "$out/kexec$i.conf" | cut -d' ' -f1)")
done
policy=(--trusted-efi "$next_digest" "${file_policy[@]}")
launch=$(python3 "$attest" measure "$out/run/vmlinux" --initrd "$out/run/initrd" \
    --cmdline "console=hvc0 attest_nonce=$nonce kexec_done")
python3 "$attest" verify "$out/run/report" "$out/run/evidence" --data "$nonce" --launch "$launch" \
    "${policy[@]}" --ek-ca "$ca" > "$out/run/verified.json" || fail "verify kexec evidence"
[ "$(json "$out/run/verified.json" 'd["host"]["kexec"]')" = "$hops" ] || fail "kexec count"
[ "$(json "$out/run/verified.json" 'd["host"]["kexec_events"][0]["initrd"]')" = "$initrd_digest" ] || fail "initrd digest output"
for i in $(seq 1 "$hops"); do
    [ "$(json "$out/run/verified.json" "d['host']['kexec_events'][$((i - 1))]['config']")" = \
        "$(sha256sum "$out/kexec$i.conf" | cut -d' ' -f1)" ] || fail "config digest output $i"
done
python3 - "$attest" "$out/run/evidence" <<'PY'
import importlib.util, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("attest", sys.argv[1])
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
ev = a.cbor_decode(open(sys.argv[2], "rb").read())
assert list(ev) == ["v", "ak", "key", "klog", "pcrs", "kexec", "quote", "ekcert", "quotesig"], list(ev)
PY
! python3 "$attest" verify "$out/run/report" "$out/run/evidence" --data "$nonce" --launch "$launch" --ek-ca "$ca" "${file_policy[@]}" >/dev/null 2>&1 \
    || fail "kexec accepted without a trusted EFI policy"
! python3 "$attest" verify "$out/run/report" "$out/run/evidence" --data "$nonce" --launch "$launch" \
    "${policy[@]}" --require-cold-boot --ek-ca "$ca" >/dev/null 2>&1 || fail "cold-boot policy accepted kexec"
python3 - "$out/run" "$hops" <<'PY'
import struct, sys
from pathlib import Path
p = Path(sys.argv[1])
data = bytearray((p / "evidence").read_bytes())
at = data.find(b"L4HKXLOG")
assert at >= 0
extra = bytearray(data)
struct.pack_into("<I", extra, at + 12, int(sys.argv[2]) + 1)
(p / "bad-extra").write_bytes(extra)
missing = bytearray(data)
missing[at + 16:at + 48] = bytes(32)
(p / "bad-missing").write_bytes(missing)
key = bytearray(data)
key[at + 16] ^= 1
(p / "bad-key").write_bytes(key)
PY
for bad in bad-extra bad-missing bad-key; do
    ! python3 "$attest" verify "$out/run/report" "$out/run/$bad" --data "$nonce" --launch "$launch" \
        "${policy[@]}" --ek-ca "$ca" >/dev/null 2>&1 || fail "$bad accepted"
done
echo "KEXECATTEST: quote, PCR14/PCR15 replay and tamper rejection passed"
