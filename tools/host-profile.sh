# SPDX-License-Identifier: GPL-2.0-only
# shellcheck shell=bash
# Source after setting root. The cargo profile the host components and
# l4h-root build with, and the directory under host/target/<target>/
# they land in: L4H_RELEASE=1 builds the cargo release profile (shipped
# images), otherwise the dev profile.  tools/build-host*.sh build there,
# and everything that boots or packages their ELFs reads them from there.
if [ "${L4H_RELEASE:-0}" = 1 ]; then
    l4h_profile=release
    l4h_cargo_profile=(--release)
else
    l4h_profile=debug
    l4h_cargo_profile=()
fi
