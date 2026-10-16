# Vendored browser modules

These browser modules are served directly from the application; there is no runtime CDN or frontend build. Their exact checked-in bytes are pinned by SHA-256:

- `preact.module.js` — `9ba8bb591b0c9a72132ff65a76e69c5a4e49cf71721b47b659f3243658bde05b`; upstream project: https://github.com/preactjs/preact; MIT terms in `PREACT-LICENSE`.
- `htm.module.js` — `ab33dd3f38059b9be4d5f5350128eefb2356639c4e0bbe9d9e8b3ba75847e9e4`; upstream project: https://github.com/developit/htm; Apache-2.0 terms in `HTM-LICENSE`.

Update a vendored module only by replacing its file, reviewing the upstream release and license, and updating this digest.
