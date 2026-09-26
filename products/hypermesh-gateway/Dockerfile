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
COPY core/lib/controlplane-core ./core/lib/controlplane-core
COPY products/hypermesh-gateway ./products/hypermesh-gateway
# Ticket verify (honor_ticket) only. Not a uv workspace member; do not COPY products/hypermesh.
COPY products/hypermesh/src/hypermesh_service/__init__.py /opt/hypermesh/src/hypermesh_service/__init__.py
COPY products/hypermesh/src/hypermesh_service/ticket.py /opt/hypermesh/src/hypermesh_service/ticket.py
ARG CONTROLPLANE_SERVICEBUS=0
RUN uv sync --frozen --no-dev --package hypermesh-gateway-service \
 && if [ "$CONTROLPLANE_SERVICEBUS" = "1" ]; then uv pip install --python /app/.venv 'azure-servicebus>=7.12.0'; fi
ENV PYTHONPATH=/app/core/lib/controlplane-core/src:/app/core/lib/controlplane-db/src:/app/core/events/src:/app/products/hypermesh-gateway/src:/opt/hypermesh/src
WORKDIR /app/products/hypermesh-gateway
CMD ["uv", "run", "--project", "/app/products/hypermesh-gateway", "python", "-m", "hypermesh_gateway_service.main"]
