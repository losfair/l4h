#!/usr/bin/env bash
# A software TPM 2.0 for QEMU (swtpm), with an EK certificate from a local
# CA, as a manufacturer provisions one.
# Usage: swtpm.sh <state dir>
# Creates the state on first use (the CA is <state dir>/ca/issuercert.pem);
# with SWTPM_EK_CERT=0, without an EK certificate in NV, as AMD's fTPM.
# and runs swtpm in the background; QEMU connects to <state dir>/sock:
#   -chardev socket,id=tpm,path=<state dir>/sock
#   -tpmdev emulator,id=tpm0,chardev=tpm -device tpm-crb,tpmdev=tpm0
# swtpm exits when QEMU does.
set -euo pipefail
dir=$(mkdir -p "$1" && cd "$1" && pwd)
if [ ! -f "$dir/tpm2-00.permall" ]; then
    mkdir -p "$dir/ca"
    cat > "$dir/swtpm_setup.conf" <<CONF
create_certs_tool = /usr/bin/swtpm_localca
create_certs_tool_config = $dir/swtpm-localca.conf
create_certs_tool_options = $dir/swtpm-localca.options
active_pcr_banks = sha256
CONF
    cat > "$dir/swtpm-localca.conf" <<CONF
statedir = $dir/ca
signingkey = $dir/ca/signkey.pem
issuercert = $dir/ca/issuercert.pem
certserial = $dir/ca/certserial
CONF
    cat > "$dir/swtpm-localca.options" <<CONF
--platform-manufacturer l4h
--platform-version 1.0
--platform-model QEMU
CONF
    cert=(--create-ek-cert)
    [ "${SWTPM_EK_CERT:-1}" != 0 ] || cert=()
    swtpm_setup --tpm2 --tpmstate "$dir" --config "$dir/swtpm_setup.conf" \
        "${cert[@]}" --lock-nvram --overwrite >"$dir/setup.log" 2>&1 \
        || { cat "$dir/setup.log" >&2; exit 1; }
fi
rm -f "$dir/sock"
swtpm socket --tpm2 --tpmstate dir="$dir" --ctrl type=unixio,path="$dir/sock" \
    --terminate --daemon --log file="$dir/swtpm.log"
for _ in $(seq 50); do [ -S "$dir/sock" ] && exit 0; sleep 0.1; done
echo "swtpm did not start (see $dir/swtpm.log)" >&2
exit 1
