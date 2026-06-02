#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
export SCRIPTD_ROOT_DIR="${SCRIPTD_ROOT_DIR:-${ROOT_DIR}}"
export SCRIPTD_ENTRY_SHELL_PATH="${SCRIPTD_ENTRY_SHELL_PATH:-${ROOT_DIR}/scriptd.sh}"
REPO_BIN="${ROOT_DIR}/target/release/scriptd"

resolve_stable_toolchain_bin_dir() {
  if ! command -v rustup >/dev/null 2>&1; then
    return 1
  fi

  local cargo_path
  local rustc_path
  cargo_path="$(rustup which --toolchain stable cargo 2>/dev/null || true)"
  rustc_path="$(rustup which --toolchain stable rustc 2>/dev/null || true)"
  if [[ -z "${cargo_path}" || -z "${rustc_path}" ]]; then
    return 1
  fi

  dirname "${cargo_path}"
}

run_cargo() {
  local toolchain_bin
  if toolchain_bin="$(resolve_stable_toolchain_bin_dir)"; then
    PATH="${toolchain_bin}:${PATH}" \
      CARGO="${toolchain_bin}/cargo" \
      RUSTC="${toolchain_bin}/rustc" \
      "${toolchain_bin}/cargo" "$@"
    return
  fi

  if command -v cargo >/dev/null 2>&1; then
    cargo "$@"
    return
  fi

  echo "Could not locate a Rust runtime (cargo or rustup stable toolchain)." >&2
  exit 1
}

release_binary_is_stale() {
  if [[ ! -x "${REPO_BIN}" ]]; then
    return 0
  fi

  if [[ "${ROOT_DIR}/Cargo.toml" -nt "${REPO_BIN}" ]]; then
    return 0
  fi

  if [[ -f "${ROOT_DIR}/Cargo.lock" && "${ROOT_DIR}/Cargo.lock" -nt "${REPO_BIN}" ]]; then
    return 0
  fi

  if [[ -f "${ROOT_DIR}/build.rs" && "${ROOT_DIR}/build.rs" -nt "${REPO_BIN}" ]]; then
    return 0
  fi

  if find "${ROOT_DIR}/src" "${ROOT_DIR}/modules" -type f -name '*.rs' -newer "${REPO_BIN}" -print -quit 2>/dev/null | grep -q .; then
    return 0
  fi

  return 1
}

ensure_release_binary() {
  if ! release_binary_is_stale; then
    return 0
  fi

  echo "Rebuilding ${REPO_BIN##*/} release binary..." >&2
  run_cargo build --release
}

if [[ "${1-}" == "test" ]]; then
  run_cargo test -- --nocapture
  exit $?
fi

ensure_release_binary
exec "${REPO_BIN}" "$@"
