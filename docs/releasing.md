# Releasing

Package `hypermesh-gateway-service` is version **0.1.0** (`pyproject.toml`). The release line recorded in `release-policy.json` and used by `.github/workflows/release.yml` is **0.1**.

## Qualify a checkout

From a tree with Python 3.13 and uv 0.11.26:

```bash
bash scripts/check-package.sh
```

That command checks `uv.lock`, runs the test suite from source, builds a wheel and runs the suite against a clean install of that wheel, then rebuilds the wheel from the source distribution and runs the suite again. Wheel runtime files and bundled resource bytes are compared with the source tree. The run also checks the built contract against `releases/prepared/release.json`.

```bash
bash scripts/check-package.sh --fixtures
```

The `--fixtures` form runs the same source, wheel, and rebuilt-archive consumers using the dependency wheels recorded under `tests_artifacts/dependencies`. Those wheels are built from the pinned public revisions. The manifest records the revisions, wheel digests, and build provenance. The verifier checks root metadata, the lock graph, and transitive wheel metadata.

Set `RELEASE_ARTIFACT_DIR` to keep the wheel and source archive that qualification produced:

```bash
export RELEASE_ARTIFACT_DIR="$(mktemp -d)"
bash scripts/check-package.sh
```

## What main retains

`.github/workflows/package.yml` runs qualification on `main` and uploads two Actions artifacts:

- `tested-dist` — the wheel and source archive from that run (retained 90 days)
- `tested-runtime-image` — the runtime image archive, its SHA256, the local image reference, and the input manifest (retained 7 days)

A later publication loads those bytes. It rebuilds nothing and does not replace an artifact that was already published. A merge to `main` stores the artifacts. It does not create a Git tag or a GitHub Release.

## Development snapshots

GitHub releases named `test-<commit>` are development snapshots. The package version embedded in a snapshot does not reserve a stable version. Snapshot records live under `releases/qualification` (contract, provenance, and the original Actions run). A snapshot stays a snapshot: labeling it does not make it the accepted baseline.

## Stable publication

Push a tag `vMAJOR.MINOR.PATCH` that matches the package version on the admitted commit. `.github/workflows/release.yml` then:

1. Runs the shared component-release workflow in [hyperme-sh/spanopticon](https://github.com/hyperme-sh/spanopticon) (pinned in the workflow file) with release line `0.1` and baseline repository variable `SPANOPTICON_RELEASE_BASELINE_SHA`.
2. On admission success, runs the pinned package publisher. The publisher reads the package workflow’s retained artifacts and attaches those bytes to the release.

`SPANOPTICON_RELEASE_BASELINE_SHA` is the full 40-character commit SHA of an accepted stable release whose bundle is `releases/accepted/release.json`. Admission stops when that variable is unset or does not point at an accepted baseline. The first baseline needs the qualified artifacts, consumer runs, and provenance from a real release. Example digests are not evidence.

`releases/prepared` names the wheel this tree is prepared to qualify, by digest, plus its contract: runtime resources, Python constraint, dependencies, extras, and entry points. `releases/prepared/dependency-transition.json` lists a pin change when one is being qualified. Runtime bytes, Python constraints, registry requirements, extras, and entry points stay the same across that transition.

The admission checklist and manifest rules are in [Release compatibility](release-policy.md) and the [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md).

## Runtime image

The image is built from the qualified wheel and the locked public requirements, not from an editable checkout or a host virtualenv.

```bash
export RELEASE_ARTIFACT_DIR="$(mktemp -d)"
bash scripts/check-package.sh
bash scripts/check-runtime-image.sh
```

`scripts/prepare-runtime-context.py` fills the build context with the checked wheel, hash-locked requirements, digest-checked dependency artifacts that match the lock graph, and an input manifest. The context has no Git credentials and no source checkout. `Dockerfile` installs those wheels into a fresh interpreter and installs `iproute2` and `wireguard-tools`. `docker-entrypoint.sh` exits if `ip` or `wg` is missing.

`scripts/check-runtime-image.sh` builds that image and runs it with no network, no capabilities, and no tun device. The probe imports the installed package, runs `ip -Version` and `wg --version`, and checks that hiding those tools makes startup fail. Configuring peers, completing a handshake, and passing overlay traffic happen after deployment, on a host that has `NET_ADMIN` and `/dev/net/tun`. The Dockerfile grants neither capability nor published ports. The image label `org.opencontainers.image.source` is `https://github.com/hyperme-sh/hypermesh-gateway`.
