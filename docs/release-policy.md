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

1. Produce a real accepted bundle at `releases/accepted/release.json`, with its
   contract files and immutable artifact references. Set the repository variable
   `SPANOPTICON_RELEASE_BASELINE_SHA` to its full 40-character commit SHA. The first
   baseline needs automated artifact/consumer qualification and provenance;
   examples and invented digests are not accepted release evidence.
2. Generate the candidate bundle at `releases/candidate/release.json` from the
   release artifacts. It must contain exactly this component, use line `0.24`,
   and match every declared owning package version and the requested tag/version.
3. Run admission against the trusted baseline. Patch contracts must remain
   unchanged; changing a published artifact at the same version is rejected.
   Verify artifact provenance and downstream consumer behavior separately.
4. Make successful admission and artifact/consumer validation automated
   prerequisites of the publisher for the exact release. Select the accepted
   baseline independently of candidate data and retain the validation evidence.
   This is pipeline validation, not a branch protection or human approval rule.

Missing baselines fail closed. This workflow neither publishes nor deploys and
does not enable repository Actions, grant private dependency access, or prove
that a declared artifact exists. See the [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md)
for the manifest format and compatibility rules.

Do not add required reviewers, branch protections, approval rulesets, environment
approvals, CODEOWNERS approval requirements, or release/deployment approval gates
unless the user explicitly requests that specific change. This includes production
releases. Automated tests and advisory reviews are welcome; human approval
prerequisites are not. GitHub plan upgrades are not release-adoption prerequisites.
