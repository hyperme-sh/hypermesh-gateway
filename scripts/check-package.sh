#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset PYTHONPATH UV_NO_SYNC
sync_options=()
run_options=()
export_options=()
fixture_wheels=()
case "${1:-}" in
  '') uv lock --check ;;
  --fixtures)
    fixture_paths=$(python3 scripts/verify_dependency_fixtures.py "$PWD")
    mapfile -t fixture_wheels <<< "$fixture_paths"
    run_options=(--no-sync)
    sync_options+=(--no-install-package controlplane-api)
    export_options+=(--no-emit-package controlplane-api)
    sync_options+=(--no-install-package controlplane-core)
    export_options+=(--no-emit-package controlplane-core)
    sync_options+=(--no-install-package controlplane-db)
    export_options+=(--no-emit-package controlplane-db)
    sync_options+=(--no-install-package controlplane-events)
    export_options+=(--no-emit-package controlplane-events)
    sync_options+=(--no-install-package controlplane-identity)
    export_options+=(--no-emit-package controlplane-identity)
    sync_options+=(--no-install-package controlplane-tenancy)
    export_options+=(--no-emit-package controlplane-tenancy)
    sync_options+=(--no-install-package hypermesh-ticket)
    export_options+=(--no-emit-package hypermesh-ticket)
    sync_options+=(--no-install-package operator-ban-store)
    export_options+=(--no-emit-package operator-ban-store)
    ;;
  *) echo 'Usage: bash scripts/check-package.sh [--fixtures]' >&2; exit 2 ;;
esac
if (( $# > 1 )); then echo 'Unexpected arguments' >&2; exit 2; fi
uv sync --frozen --python 3.13 "${sync_options[@]}"
if (( ${#fixture_wheels[@]} )); then
  uv pip install --python .venv/bin/python --no-deps --reinstall "${fixture_wheels[@]}"
fi
uv run --frozen "${run_options[@]}" pytest
uv run --frozen "${run_options[@]}" pytest -q tests_tools
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
uv build --out-dir "$scratch/dist"
uv run --frozen "${run_options[@]}" python scripts/verify_wheel.py "$scratch/dist"
uv export --frozen "${export_options[@]}" --no-emit-project --format requirements-txt --output-file "$scratch/requirements.txt" >/dev/null
uv venv --python 3.13 "$scratch/venv"
uv pip sync --python "$scratch/venv/bin/python" "$scratch/requirements.txt"
if (( ${#fixture_wheels[@]} )); then
  uv pip install --python "$scratch/venv/bin/python" --no-deps "${fixture_wheels[@]}" "$scratch"/dist/*.whl
else
uv pip uninstall --python "$scratch/venv/bin/python" controlplane-core controlplane-api controlplane-tenancy controlplane-identity controlplane-db controlplane-events operator-ban-store hypermesh-ticket
uv pip install --python "$scratch/venv/bin/python" --constraint "$scratch/requirements.txt" "$scratch"/dist/*.whl
fi
cp -R tests "$scratch/"
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null -o asyncio_mode=auto -o asyncio_default_fixture_loop_scope=function tests)
# Rebuild from the sdist; a checkout must not supply omitted package files.
uv run --frozen "${run_options[@]}" python - "$scratch" <<'PY'
import pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
with tarfile.open(next((root / 'dist').glob('*.tar.gz'))) as archive:
    archive.extractall(root / 'sdist', filter='data')
PY
uv build --wheel "$scratch"/sdist/* --out-dir "$scratch/rebuilt"
uv run --frozen "${run_options[@]}" python scripts/verify_wheel.py "$scratch/rebuilt"
uv pip install --python "$scratch/venv/bin/python" --no-deps --reinstall "$scratch"/rebuilt/*.whl
(cd "$scratch" && "$scratch/venv/bin/python" -I -m pytest -c /dev/null -o asyncio_mode=auto -o asyncio_default_fixture_loop_scope=function tests)

# Retain the exact validated bytes for the release channel; never rebuild them.
if [[ -n "${RELEASE_ARTIFACT_DIR:-}" ]]; then
  mkdir -p "$RELEASE_ARTIFACT_DIR"
  cp "$scratch/dist"/* "$RELEASE_ARTIFACT_DIR/"
fi

if [[ -n "${PREPARATION_EVIDENCE_DIR:-}" ]]; then
  python3 scripts/export_release_contract.py "$scratch"/dist/*.whl --output "$PREPARATION_EVIDENCE_DIR"
fi
