# Release compatibility

This component targets the shared **0.24.x** release line. Components share major
and minor versions; patch numbers advance independently and must preserve their
accepted API contracts. Existing package versions are retained until a qualified
release is prepared; installing this workflow does not qualify those versions.

`release-policy.json` identifies the owner and every owning package version file.
The pinned Spanopticon workflow checks this configuration on pull requests.
Version changes or a `releases/candidate/release.json` submission also require
release admission. Every tag push and manual release request requires admission.
A configuration-only result is not a release compatibility result.

Before attempting a release:

1. Review a real accepted bundle at `releases/accepted/release.json`, with its
   contract files and immutable artifact references. Set the repository variable
   `SPANOPTICON_RELEASE_BASELINE_SHA` to its full 40-character commit SHA. The first
   baseline needs explicit owner review and artifact/consumer qualification;
   examples and invented digests are not accepted release evidence.
2. Generate the candidate bundle at `releases/candidate/release.json` from the
   release artifacts. It must contain exactly this component, use line `0.24`,
   and match every declared owning package version and the requested tag/version.
3. Run admission against the trusted baseline. Patch contracts must remain
   unchanged; changing a published artifact at the same version is rejected.
   Verify artifact provenance and downstream consumer behavior separately.
4. Make admission a required check and a prerequisite of any publisher, and
   protect the workflow, version-source configuration and baseline variable.
   Repository plan and Actions access must support those controls before
   declaring release enforcement active.

Missing baselines fail closed. This workflow neither publishes nor deploys and
does not enable repository Actions, grant private dependency access, or prove
that a declared artifact exists. See the [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md)
for the manifest format and compatibility rules.
