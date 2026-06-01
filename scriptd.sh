#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENTRYPOINT="${ROOT_DIR}/src/main.ts"
USER_ARGS=("$@")

export SCRIPTD_ROOT_DIR="${SCRIPTD_ROOT_DIR:-${ROOT_DIR}}"
export SCRIPTD_ENTRY_SHELL_PATH="${ROOT_DIR}/scriptd.sh"

try_runtime() {
  if "$@" "${ENTRYPOINT}" __runtime_probe >/dev/null 2>&1; then
    exec "$@" "${ENTRYPOINT}" "${USER_ARGS[@]}"
  fi
}

try_runtime bun
try_runtime node --experimental-strip-types
try_runtime npx tsx

echo "Could not run src/main.ts with bun, node --experimental-strip-types, or npx tsx." >&2
exit 1
