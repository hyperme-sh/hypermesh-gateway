#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RELEASE_ARTIFACT_DIR:?Run package qualification and retain its exact wheels first}"
scratch=$(mktemp -d)
image="hypermesh-gateway:qualification-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-${BASHPID}"
probe=''
cleanup() {
  if [[ -n "$probe" ]]; then rm -f "$probe"; fi
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT
source_sha=$(git rev-parse HEAD)
probe=$(mktemp "$PWD/scripts/runtime-input-probe.XXXXXX")
if python3 scripts/prepare-runtime-context.py --artifacts "$RELEASE_ARTIFACT_DIR" \
    --output "$scratch/rejected-context" --source-sha "$source_sha" >"$scratch/untracked.out" 2>&1; then
  echo 'Untracked runtime input was accepted' >&2
  exit 1
fi
grep -F 'Runtime inputs include changes outside the selected source commit' "$scratch/untracked.out" >/dev/null
rm -f "$probe"
probe=''
python3 scripts/prepare-runtime-context.py --artifacts "$RELEASE_ARTIFACT_DIR" \
  --output "$scratch/context" --source-sha "$source_sha"
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker build --build-arg "SOURCE_SHA=$source_sha" --build-arg "BUILT_AT=$built_at" \
  -t "$image" "$scratch/context"
# No tun, NET_ADMIN, peer configuration, live hosts or provider calls in package CI.
docker run --rm --network none --cap-drop ALL --read-only \
  --env HYPERMESH_WG_APPLY=0 --env HYPERMESH_ASSIGNMENT_REFRESH_S=0 \
  "$image" /app/.venv/bin/python -I -c '
import importlib, json, shutil, subprocess
assert shutil.which("ip") and shutil.which("wg")
subprocess.run(["ip", "-Version"], check=True)
subprocess.run(["wg", "--version"], check=True)
module = importlib.import_module("hypermesh_gateway_service")
assert "/site-packages/" in module.__file__
from hypermesh_gateway_service.app import create_app
assert create_app().openapi()["paths"]
print(json.dumps({"installed_gateway": True, "wireguard_tools_available": True}))'
status=0
docker run --rm --network none --cap-drop ALL --read-only --env PATH=/app/.venv/bin \
  "$image" >"$scratch/missing.out" 2>&1 || status=$?
test "$status" = 78
grep -F 'Missing WireGuard runtime tool:' "$scratch/missing.out" >/dev/null
if [[ -n "${RUNTIME_IMAGE_OUTPUT_DIR:-}" ]]; then
  mkdir -p "$RUNTIME_IMAGE_OUTPUT_DIR"
  docker save "$image" -o "$RUNTIME_IMAGE_OUTPUT_DIR/image.tar"
  sha256sum "$RUNTIME_IMAGE_OUTPUT_DIR/image.tar" | cut -d ' ' -f 1 > "$RUNTIME_IMAGE_OUTPUT_DIR/image.sha256"
  printf '%s\n' "$image" > "$RUNTIME_IMAGE_OUTPUT_DIR/image.ref"
  cp "$scratch/context/runtime-inputs.json" "$RUNTIME_IMAGE_OUTPUT_DIR/"
fi
