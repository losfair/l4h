#!/usr/bin/env bash
# Attestation (DESIGN.md §10.2) end to end: UEFI boot with a software TPM
# (swtpm), dom0 and a guest it starts get reports, tools/l4h-attest.py
# verifies them against the host evidence and makes a credential for the
# attestation key, which dom0 decrypts on a second boot (TIS this time,
# CRB the first).  A third boot has the TPM look like an AMD fTPM: the
# ACPI start method, through a _DSM in AML (tests/ftpm), which trustd
# runs for every command; GRUB swaps QEMU's TPM2 table for ours.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source "$root/tools/guest-env.sh"
out=$root/build/attest
rm -rf "$out/run" && mkdir -p "$out/run"
"$root/tools/build-linux.sh" vmlinux >"$root/build/linux-build.log" 2>&1 \
    || { grep -E "error|undefined" "$root/build/linux-build.log"; exit 1; }
"$l4h_objcopy" --strip-debug "$l4h_linux_out/vmlinux" "$out/run/vmlinux"
"$root/tools/build-l4hctl.sh"
"$root/tests/build-flagstest.sh"
"$root/tools/build-host.sh"
"$root/tools/mkinitramfs.sh" "$out/run/vm.cpio.gz" "$root/tests/guest/init-attestvm" "$l4h_ctl" >/dev/null
nonce=$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
cmdline="console=hvc0 attest_nonce=$nonce"
cat > "$out/run/l4h.conf" <<CONF
# tests/run-attesttest.sh
dom0_disks=0
dom0_cmdline="$cmdline"
CONF
# A fresh TPM, so that the EK certificate is the one from this CA.
rm -rf "$out/tpm"
attest=$root/tools/l4h-attest.py
# Extra QEMU arguments, and environment for tools/mkimage.sh, of the next
# boot.
qemu_extra=() image_env=()
boot() {  # boot <name> <tpm-crb|tpm-tis> [extra initramfs files...]
    local name=$1 dev=$2
    shift 2
    "$root/tools/mkinitramfs.sh" "$out/run/$name.cpio.gz" "$root/tests/guest/init-attest" \
        "$l4h_ctl" "$out/run/vm.cpio.gz" "$@" >/dev/null
    env "${image_env[@]}" L4H_GUEST_KERNEL="$out/run/vmlinux" L4H_GUEST_KMODS= \
        "$root/tools/mkimage.sh" -i "$out/run/$name.cpio.gz" -c "$out/run/l4h.conf" \
        "$out/run/$name.raw" >/dev/null
    "$root/tools/swtpm.sh" "$out/tpm"
    local log=$out/$name.log  # build/*/*.log: kept by CI on failure
    timeout "${ATTESTTEST_TIMEOUT:-180}" "$root/tools/run-uefi.sh" "$out/run/$name.raw" \
        -chardev socket,id=tpm,path="$out/tpm/sock" -tpmdev emulator,id=tpm0,chardev=tpm \
        -device "$dev",tpmdev=tpm0 "${qemu_extra[@]}" </dev/null >"$log" 2>&1 &
    local qemu=$!
    while kill -0 "$qemu" 2>/dev/null; do
        grep -aq "ATTEST: done\|l4h-vmmgr: all guests stopped" "$log" && { sleep 1; kill "$qemu"; break; }
        sleep 1
    done
    wait "$qemu" 2>/dev/null || true
    grep -aE "ATTEST|trustd|TPM|panic" "$log" | cut -c1-160 || true
}
# The hex of the first line of a log that is "<what> <hex>" and nothing
# else: prints from other cores (the serial copy of a guest's console,
# "[vm1] ...") can interleave with a line, character by character.
field() {  # field <log> <what> <out file>
    sed -E 's/^\[vm[0-9]+\] //' "$1" | grep -a "^$2 [0-9a-f]*"$'\r'"*$" | head -1 | tr -d '\r' | sed "s/^$2 //" \
        | python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))" > "$3"
    [ -s "$3" ] || { echo "no $2 in $1"; exit 1; }
}
fail() { echo "ATTESTTEST: FAIL: $*"; exit 1; }

boot boot1 tpm-crb "$root/build/guest/flags-test" "$root/build/guest/flagsvm.cpio.gz"
log=$out/boot1.log
field "$log" "ATTEST: dom0 report" "$out/run/dom0.report"
field "$log" "ATTEST: evidence" "$out/run/evidence1"
field "$log" "ATTESTVM: report" "$out/run/vm.report"
grep -aq "ATTEST: tsm provider l4h" "$log" || fail "no configfs-tsm provider"
grep -aq "ATTEST: tsm report matches" "$log" || fail "configfs-tsm report differs"
grep -aq "ATTEST: tsm evidence matches" "$log" || fail "configfs-tsm evidence differs"
dom0_launch=$(python3 "$attest" measure "$out/run/vmlinux" --initrd "$out/run/boot1.cpio.gz" --cmdline "$cmdline")
vm_launch=$(python3 "$attest" measure "$out/run/vmlinux" --initrd "$out/run/vm.cpio.gz" --cmdline "$cmdline")
ca=$out/tpm/ca/issuercert.pem
python3 "$attest" verify "$out/run/dom0.report" "$out/run/evidence1" --data "$nonce" \
    --launch "$dom0_launch" --ek-ca "$ca" > "$out/run/dom0.json" || fail "dom0 report"
python3 "$attest" verify "$out/run/vm.report" "$out/run/evidence1" --data "$nonce" \
    --launch "$vm_launch" --ek-ca "$ca" > "$out/run/vm.json" || fail "guest report"
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))" "$@"; }
[ "$(json "$out/run/dom0.json" 'd["guest"]["dom0"]')" = True ] || fail "dom0 not marked dom0"
[ "$(json "$out/run/vm.json" 'd["guest"]["dom0"]')" = False ] || fail "guest marked dom0"
[ "$(json "$out/run/vm.json" 'd["guest"]["ram"]')" = $((64 << 20)) ] || fail "guest RAM"
# The firmware and GRUB measured the boot.
[ "$(json "$out/run/dom0.json" 'd["host"]["pcrs"]["4"]')" != "$(printf '0%.0s' $(seq 64))" ] || fail "PCR 4 empty"
[ "$(json "$out/run/dom0.json" 'd["host"]["pcrs"]["9"]')" != "$(printf '0%.0s' $(seq 64))" ] || fail "PCR 9 empty"
# Tampering is caught.
cp "$out/run/dom0.report" "$out/run/bad.report"
printf '\x00' | dd of="$out/run/bad.report" bs=1 seek=40 conv=notrunc status=none
! python3 "$attest" verify "$out/run/bad.report" "$out/run/evidence1" 2>/dev/null || fail "tampered report verified"
! python3 "$attest" verify "$out/run/vm.report" "$out/run/evidence1" --launch "$dom0_launch" 2>/dev/null \
    || fail "wrong launch digest accepted"
ak=$(json "$out/run/dom0.json" 'd["host"]["ak_name"]')
echo "ATTESTTEST: reports verify; AK $ak"

grep -aq "FLAGS: PASS" "$log" || fail "dom0 flags checks"
grep -aq "FLAGVM: PASS" "$log" || fail "guest flags checks"
! grep -aq "FLAGS: FAIL\|FLAGVM: FAIL" "$log" || fail "flags guest failed"
for phase in clean injected gates fresh queued; do
    field "$log" "FLAGVM: $phase report" "$out/run/$phase.report"
done
python3 "$attest" verify "$out/run/clean.report" "$out/run/evidence1" --data "$nonce" \
    --require-seal console-out > "$out/run/clean.json" || fail "clean sealed report"
! python3 "$attest" verify "$out/run/injected.report" "$out/run/evidence1" >/dev/null 2>&1 || fail "injected input accepted"
python3 "$attest" verify "$out/run/injected.report" "$out/run/evidence1" --deny-taint '' > "$out/run/injected.json" || fail "allow input"
python3 "$attest" verify "$out/run/gates.report" "$out/run/evidence1" --deny-taint 130,131 \
    --require-seal console-in,console-out,130,140-141 > "$out/run/gates.json" || fail "guest gates"
python3 "$attest" verify "$out/run/fresh.report" "$out/run/evidence1" > "$out/run/fresh.json" || fail "new instance"
python3 "$attest" verify "$out/run/queued.report" "$out/run/evidence1" --deny-taint '' > "$out/run/queued.json" || fail "pre-start input"
python3 - "$out/run" <<'CHECK'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
def guest(phase):
    return json.loads((p / (phase + '.json')).read_text())['guest']
clean, injected, gates, fresh, queued = map(guest, ['clean', 'injected', 'gates', 'fresh', 'queued'])
assert int.from_bytes(bytes.fromhex(clean['taint']), 'little') == 0
assert int.from_bytes(bytes.fromhex(clean['seal']), 'little') == 2
assert injected['taint_bits'] == ['0(console-in)']
assert gates['taint_bits'] == ['0(console-in)', '65(F)', '140', '141', '200']
assert fresh['taint_bits'] == fresh['seal_bits'] == []
assert queued['taint_bits'] == ['0(console-in)']
assert clean['guest'] == fresh['guest'] == queued['guest']
assert clean['instance'] < fresh['instance'] < queued['instance']
CHECK
echo "ATTESTTEST: taint, seals, at-most-once gates and reused instances verify"


secret=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
python3 "$attest" make-credential "$out/run/evidence1" "$secret" -o "$out/run/cred" || fail "make-credential"
boot boot2 tpm-tis "$out/run/cred"
log=$out/boot2.log
grep -aq "ATTEST: secret $secret" "$log" || fail "credential not activated"
# trustd's per-guest ActivateCredential limit: a burst of 5, then -EAGAIN.
grep -aq "ATTEST: limited after 5: .*Resource temporarily unavailable" "$log" || fail "activation not rate limited"
grep -aq "ATTEST: activated after a pause" "$log" || fail "activation not allowed again after a pause"
field "$log" "ATTEST: dom0 report" "$out/run/dom0.report2"
field "$log" "ATTEST: evidence" "$out/run/evidence2"
python3 "$attest" verify "$out/run/dom0.report2" "$out/run/evidence2" --data "$nonce" --ak-name "$ak" \
    --ek-ca "$ca" > "$out/run/dom0.json2" || fail "second boot report"
[ "$(json "$out/run/dom0.json2" 'd["host"]["key"]')" != "$(json "$out/run/dom0.json" 'd["host"]["key"]')" ] \
    || fail "same host key on both boots"
echo "ATTESTTEST: TIS, the credential and its rate limit work"

for t in tpm2 ssdt; do
    iasl -p "$out/run/$t" "$root/tests/ftpm/$t.asl" >"$out/run/iasl.log" 2>&1 || fail "iasl $t.asl"
done
secret=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
python3 "$attest" make-credential "$out/run/evidence1" "$secret" -o "$out/run/cred" || fail "make-credential"
image_env=(L4H_ACPI_TABLES="$out/run/tpm2.aml $out/run/ssdt.aml" L4H_ACPI_EXCLUDE=TPM2)
qemu_extra=(-chardev file,id=dbg,path="$out/run/debugcon" -device isa-debugcon,iobase=0x402,chardev=dbg)
boot boot3 tpm-crb "$out/run/cred"
log=$out/boot3.log
grep -aq "TPM 2.0 (CRB, ACPI start)" "$log" || fail "not the ACPI start method"
starts=$(tr -cd S < "$out/run/debugcon" | wc -c)
[ "$starts" -ge 10 ] || fail "only $starts starts through _DSM"
grep -aq "ATTEST: secret $secret" "$log" || fail "credential not activated (ACPI start)"
field "$log" "ATTEST: dom0 report" "$out/run/dom0.report3"
field "$log" "ATTEST: evidence" "$out/run/evidence3"
python3 "$attest" verify "$out/run/dom0.report3" "$out/run/evidence3" --data "$nonce" --ak-name "$ak" \
    --ek-ca "$ca" > "$out/run/dom0.json3" || fail "ACPI start report"
echo "ATTESTTEST: ACPI start method: $starts commands through _DSM"
echo "ATTESTTEST: PASS"
