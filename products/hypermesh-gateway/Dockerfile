FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml uv.lock ./
COPY core/lib/controlplane-db ./core/lib/controlplane-db
COPY scripts/alembic_head.py /tmp/alembic_head.py
ARG ALEMBIC_HEAD
# Bake the Alembic head from the migrations copied above. See scripts/alembic_head.py.
RUN python3 /tmp/alembic_head.py \
      --versions /app/core/lib/controlplane-db/src/controlplane_db/alembic/versions \
      --write /alembic-head \
      --expect "${ALEMBIC_HEAD}"
LABEL com.fyberlabs.alembic-head="${ALEMBIC_HEAD}"
COPY core/events ./core/events
COPY core/lib/controlplane-api ./core/lib/controlplane-api
COPY core/lib/controlplane-core ./core/lib/controlplane-core
COPY core/lib/controlplane-identity ./core/lib/controlplane-identity
COPY core/lib/controlplane-tenancy ./core/lib/controlplane-tenancy
COPY products/hypermesh-ticket ./products/hypermesh-ticket
COPY products/hypermesh-gateway ./products/hypermesh-gateway
ARG CONTROLPLANE_SERVICEBUS=0
RUN uv sync --frozen --no-dev --package hypermesh-gateway-service \
 && if [ "$CONTROLPLANE_SERVICEBUS" = "1" ]; then uv pip install --python /app/.venv 'azure-servicebus>=7.12.0'; fi
ENV PYTHONPATH=/app/core/lib/controlplane-core/src:/app/core/lib/controlplane-db/src:/app/core/events/src:/app/products/hypermesh-gateway/src
# Import the service app in the built image. A workspace package that the
# service imports but its pyproject does not declare is never installed here,
# so the import fails now and the image is not published.
RUN /app/.venv/bin/python -c "import hypermesh_gateway_service.app"
# GIT_SHA and BUILT_AT identify this image. Below the venv layer so a new
# commit does not reinstall dependencies. imagetools carry keeps these
# values. /version reports this build, not the deploy tag.
ARG GIT_SHA=
ARG BUILT_AT=
ENV GIT_SHA=${GIT_SHA}
ENV BUILT_AT=${BUILT_AT}
WORKDIR /app/products/hypermesh-gateway
CMD ["/app/.venv/bin/python", "-m", "hypermesh_gateway_service.main"]
