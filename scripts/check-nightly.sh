#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_EVENT_NAME:-}" == schedule && "${GITHUB_REF:-}" == refs/heads/main ]] || {
  echo 'Gateway full suite is restricted to the scheduled main batch' >&2
  exit 2
}
: "${NIGHTLY_OUTPUT:?Central nightly output is required}"
export GATEWAY_NIGHTLY=1
export RELEASE_ARTIFACT_DIR="$NIGHTLY_OUTPUT/package"
export RUNTIME_IMAGE_OUTPUT_DIR="$NIGHTLY_OUTPUT/runtime"
trap 'rm -rf "$RELEASE_ARTIFACT_DIR" "$RUNTIME_IMAGE_OUTPUT_DIR"' EXIT
bash scripts/check-package.sh --fixtures
bash scripts/check-runtime-image.sh
