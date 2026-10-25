#!/bin/sh
set -eu

for path in \
  assets/web \
  modules \
  schemas \
  service.yaml \
  src/supervisor.rs \
  src/triggers \
  src/modules.rs \
  src/status.rs \
  src/schema.rs \
  tests/integration.rs
 do
  if [ -e "$path" ]; then
    printf 'public bridge release blocked: legacy product source remains: %s\n' "$path" >&2
    exit 1
  fi
done

for root in crates/scriptd-bridge/src crates/scriptd-bridge-protocol/src; do
  if [ ! -d "$root" ]; then
    printf 'public bridge release blocked: production source root is missing: %s\n' "$root" >&2
    exit 1
  fi
done

set +e
crate_matches=$(grep -R -n -E 'run_supervisor|run_one_module|BuiltInModule|ServiceConfig' crates 2>&1)
status=$?
set -e
if [ "$status" -gt 1 ]; then
  printf 'public bridge release blocked: could not scan crate sources (grep exit %s)\n' "$status" >&2
  printf '%s\n' "$crate_matches" >&2
  exit "$status"
fi
if [ "$status" -eq 0 ]; then
  printf '%s\n' "$crate_matches"
  echo 'public bridge release blocked: product runtime symbols remain in the public crate sources' >&2
  exit 1
fi

set +e
manifest_matches=$(grep -n -E 'run_supervisor|run_one_module|BuiltInModule|ServiceConfig' Cargo.toml 2>&1)
status=$?
set -e
if [ "$status" -gt 1 ]; then
  printf 'public bridge release blocked: could not scan Cargo.toml (grep exit %s)\n' "$status" >&2
  printf '%s\n' "$manifest_matches" >&2
  exit "$status"
fi
if [ "$status" -eq 0 ]; then
  printf '%s\n' "$manifest_matches"
  echo 'public bridge release blocked: product runtime symbols remain in the workspace manifest' >&2
  exit 1
fi

echo 'public bridge source boundary verified'
