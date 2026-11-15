#!/usr/bin/env bash
# Downloaded sources shared by setup and the independent rebuild check.
LINUX_VERSION=6.18.63
LINUX_SHA256=81764a545072d160748beff4d9de2e7d95aa9f16e8261110288f067a2cc61d71
RUSTUP_VERSION=1.29.1
RUSTUP_SHA256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
# Cargo's trim-paths fix for dependencies outside the workspace (2026-10-24).
# Use this build tool with the existing, separately pinned Rust compilers.
L4H_CARGO_DATE=2026-11-14
L4H_CARGO_SHA256=53dc95e6912a58ae1106a6c59b6e2c48d790cbee81dd379246097ee547966609
