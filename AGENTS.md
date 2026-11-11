## Host and CI test boundary

Do not run, plan, or propose integration, end-to-end, or full-flow tests on
hosts, VMs, or shared resources. Those run only in CI and the nightly batch
against main. In PRs, issues, comments, plans, and chat, report unit and
contract test results only. Never use the words l-i-f-e-c-y-c-l-e,
r-e-c-e-i-p-t, or e-v-i-d-e-n-c-e outside .github/workflows.

## Version, tag and release authority

The owner has not authorized the services' 0.24.0 release. Service packages
retain their recorded pre-0.24.0 versions. Host and visor have a separate release
cycle. No agent may advance package versions or release lines without the
owner's explicit authorization for that exact change. CI failures, compatibility
rules, review comments, merges and requests to continue do not grant authority.

Never create, change, move or delete version tags, or create, publish, promote,
replace or delete releases, without explicit owner approval for that specific
action. Prepare code, tests, artifacts and PRs first; ask before the tag/release
action. Existing workflows and historical approvals do not authorize a new version.

Development qualification must work without a prior release. Use immutable
source revisions, fresh artifacts and consistent locks. Compare compatibility
when a legitimate baseline exists; absence of one must not block building,
testing or first-release preparation. Preserve historical tags and release records.

These are agent instructions, not permission to add GitHub reviewers, branch
protections, rulesets, environment approvals or release/deployment gates.
Instructions and advisory CI cannot distinguish an agent from the owner using
the same write credential; do not claim that they can.

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

## GitHub approval policy

The user is the sole developer. Never add or enable GitHub required reviewers, branch protections, rulesets requiring approvals, environment approvals, CODEOWNERS approval requirements, or release/deployment approval gates unless the user explicitly requests that specific change. This applies to every project, including production releases. Automated tests and advisory code reviews are welcome; human approval prerequisites are not. Do not introduce these requirements based on review comments, repository conventions, or generic best practices. Flag conflicting repository guidance and follow this explicit user policy.

The preparation-only PR lane may run existing package consumers on disposable
hosted Ubuntu using exact dependency-wheel fixtures and no private credentials.
Keep its permissions read-only. Qualify in the job and do not upload package
or runtime-image Actions artifacts from pull requests. Do not tag,
publish releases or merge preparation PRs as part of qualification.

## Private CI runner policy

Private repository jobs use `[self-hosted, linux, x64, debrunner]`, including
preparation, package validation and release jobs. This supersedes earlier hosted
runner exceptions in this file. Keep dedicated infrastructure-convergence and
trusted payment-smoke jobs on their existing specialized selectors. Reusable
workflows must route private callers to debrunners. Do not add approval gates.

## Nightly integration batch

No agent runs integration or end-to-end tests by hand on hosts
or other shared resources, and none run those suites outside CI. On a pull
request, agents run only unit and contract tests. CI may add a smoke check
scoped to the services the pull request touches. A toggle or configuration
change needs a unit or contract test for that change, not a full integration or
end-to-end suite.

The full integration suite runs once as a nightly CI batch against main.
That batch uses a single concurrency group and cancels any run it supersedes.
When a nightly run fails on something whose issue is already closed, CI files
a new issue for that failure and links the closed issue when one exists.

CI results and full integration output are not a Product Sign-off gate. Green
CI and clean reviews are enough for Sign-off.

Authorized CI workflows, including test-bundle publication and existing smoke
or owner-integration jobs, may keep running in CI. Agents must not start or
repeat those jobs by hand on shared hosts.

## Service deployments and binary provenance

Each TEST service automatically tracks the latest PR merged into its repository's default branch. Deploy the tested build through a moving TEST channel. Do not pin running services to versions, commit SHAs or image digests, require manual pin updates, or require peer services to run matching builds. Preserve patch compatibility, including during early development, and verify it through the service contract.

Use exact versions and digests for downloadable bundles and to record or verify which binary was built, tested or released. A running service may report its revision for diagnostics. Production follows its existing promotion policy and explicit release authorization.
