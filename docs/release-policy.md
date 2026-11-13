# Release compatibility

This component's release line is **0.1**, recorded in `release-policy.json` and `.github/workflows/release-admission.yml`. The package version in `pyproject.toml` is 0.1.0. Patch releases on that line keep the accepted API contract. Installing the release workflow does not publish that version.

`release-policy.json` names this repository, component `hypermesh-gateway`, release line `0.1`, and the version file `pyproject.toml`. The pinned Spanopticon workflow checks this configuration on pull requests. Version changes, and a `releases/candidate/release.json` submission, go through release admission. Every `v*` tag push goes through admission. A configuration-only result is not a compatibility result.

Before attempting a release:

1. Produce an accepted bundle at `releases/accepted/release.json`, with its contract files and immutable artifact references. Set the repository variable `SPANOPTICON_RELEASE_BASELINE_SHA` to that commit's full 40-character SHA. The first baseline needs the qualified artifacts, consumer runs, and provenance from a real release. Example digests are not release evidence.
2. Generate the candidate bundle at `releases/candidate/release.json` from the release artifacts. It must contain exactly this component, use line `0.1`, and match the package version and the requested tag.
3. Run admission against the accepted baseline. Patch contracts stay unchanged. Replacing a published artifact at the same version is rejected. Check artifact provenance and downstream consumer behavior in their own jobs.
4. Publication runs only after admission succeeds for that tag. The publisher reads the accepted baseline on its own and keeps the validation evidence.

Admission stops when `SPANOPTICON_RELEASE_BASELINE_SHA` is unset or does not point at an accepted baseline. The admission workflow publishes nothing and deploys nothing. Manifest format and compatibility rules: [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md).

Development snapshots, the accepted baseline, and the runtime image are described in [Releasing](releasing.md).
