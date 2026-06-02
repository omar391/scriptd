#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
export SCRIPTD_ROOT_DIR="${SCRIPTD_ROOT_DIR:-${ROOT_DIR}}"
export SCRIPTD_ENTRY_SHELL_PATH="${SCRIPTD_ENTRY_SHELL_PATH:-${ROOT_DIR}/scriptd.sh}"
REPO_BIN="${ROOT_DIR}/target/release/scriptd"

if [[ -x "${REPO_BIN}" ]]; then
  exec "${REPO_BIN}" "$@"
fi

if [[ "${1-}" == "test" ]]; then
  if command -v rustup >/dev/null 2>&1; then
    exec rustup run stable cargo test -- --nocapture
  fi

  if command -v cargo >/dev/null 2>&1; then
    exec cargo test -- --nocapture
  fi

  echo "Could not locate a Rust runtime (cargo or rustup)." >&2
  exit 1
fi

if command -v rustup >/dev/null 2>&1; then
  exec rustup run stable cargo run --release -- "$@"
fi

if command -v cargo >/dev/null 2>&1; then
  exec cargo run --release -- "$@"
fi

echo "Could not locate a Rust runtime (cargo)." >&2
exit 1
