# Hypermesh gateway development

Read README.md. Preserve ticket authorization, tenant boundaries, key revocation,
request limits and safety screening. Run bash scripts/check-package.sh.
Use fake control planes and mock hosts; do not apply WireGuard configuration or
contact live hosts/providers during package validation.

## Package publication permission boundary

Source/package validation keeps its existing runner policy and read-only contents.
The separate `.github/workflows/release.yml` publication job is the narrow exception:
it may use `contents: write` and `actions: read` on disposable `ubuntu-24.04` workers
solely through the exact-pinned shared package publisher. It must not check out or
execute this repository's code, install its packages, or receive private dependency
or deployment credentials. This hosted publication exception does not authorize
moving secret-bearing validation to another runner group. Stable publication must
retain any configured release-admission prerequisite for the exact tag/commit.
