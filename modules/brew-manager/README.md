brew-manager
============

This module runs Homebrew maintenance under `scriptd`.

Files
- `module.rs` — Rust plugin implementation.
- `module.yaml` — the single module manifest/config file.

Usage
- `./scriptd.sh setup brew-manager`
- `./scriptd.sh run brew-manager`
- enable or disable it from `service.yaml`
