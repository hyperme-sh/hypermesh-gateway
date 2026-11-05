# syntax=docker/dockerfile:1
# Build only the context produced by scripts/prepare-runtime-context.py.
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim@sha256:531f855bda2c73cd6ef67d56b733b357cea384185b3022bd09f05e002cd144ca AS builder
WORKDIR /app
ENV UV_HTTP_TIMEOUT=120
COPY requirements.txt /packages/requirements.txt
COPY wheels/ /packages/wheels/
RUN uv venv --python /usr/local/bin/python /app/.venv \
    && uv pip sync --python /app/.venv/bin/python --require-hashes /packages/requirements.txt \
    && uv pip install --python /app/.venv/bin/python --no-index --no-deps /packages/wheels/*.whl \
    && uv pip check --python /app/.venv/bin/python

FROM python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 wireguard-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY runtime-inputs.json /app/runtime-inputs.json
ARG SOURCE_SHA
ARG BUILT_AT
LABEL org.opencontainers.image.source="https://github.com/hyperme-sh/hypermesh-gateway" \
      org.opencontainers.image.revision="${SOURCE_SHA}"
ENV PATH="/app/.venv/bin:${PATH}" PYTHONPATH="" PYTHONDONTWRITEBYTECODE=1 \
    GIT_SHA=${SOURCE_SHA} HYPERMESH_GATEWAY_SOURCE_SHA=${SOURCE_SHA} BUILT_AT=${BUILT_AT}
# WireGuard uses the existing deployment's NET_ADMIN and tun contract.
# This image neither grants capabilities nor publishes host ports.
ENTRYPOINT ["/bin/sh", "/docker-entrypoint.sh"]
CMD ["/app/.venv/bin/python", "-I", "-m", "hypermesh_gateway_service.main"]
