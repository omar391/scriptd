# TODOs

- Finish all remaining work from the existing plans before starting any new architectural expansion.

- Keep the folder structure lean.
  Use the repository root as the `scriptd` project root.
  Prefer a top-level `src/` directory instead of `apps/scriptd/`.

- Standardize each module around a single unified manifest YAML file.
  Each module should keep one manifest/config file only, rather than splitting metadata and config across multiple files.
