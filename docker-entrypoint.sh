#!/bin/sh
set -eu
for tool in ip wg; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing WireGuard runtime tool: $tool" >&2
        exit 78
    fi
done
exec "$@"
