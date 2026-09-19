FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml uv.lock ./
COPY core/lib/controlplane-db ./core/lib/controlplane-db
COPY core/events ./core/events
COPY core/lib/controlplane-core ./core/lib/controlplane-core
COPY products/hypermesh-gateway ./products/hypermesh-gateway
# Ticket verify (honor_ticket) only. Not a uv workspace member; do not COPY products/hypermesh.
COPY products/hypermesh/src/hypermesh_service/__init__.py /opt/hypermesh/src/hypermesh_service/__init__.py
COPY products/hypermesh/src/hypermesh_service/ticket.py /opt/hypermesh/src/hypermesh_service/ticket.py
RUN uv sync --frozen --no-dev --package hypermesh-gateway-service
ENV PYTHONPATH=/app/core/lib/controlplane-core/src:/app/core/lib/controlplane-db/src:/app/core/events/src:/app/products/hypermesh-gateway/src:/opt/hypermesh/src
WORKDIR /app/products/hypermesh-gateway
CMD ["uv", "run", "--project", "/app/products/hypermesh-gateway", "python", "-m", "hypermesh_gateway_service.main"]
