from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from controlplane_api.exceptions import ForbiddenException, UnauthorizedException
from controlplane_api.logging import configure_logging
from controlplane_api.utils import get_logger
from controlplane_api.service_cors import add_optional_service_cors
from controlplane_api.health import router as health_router
from controlplane_api.version import router as version_router

from hypermesh_gateway_service.classify import Classifier, resolve_classifier
from hypermesh_gateway_service.errors import INVALID_API_KEY_MESSAGE, DoorError, openai_error_body
from hypermesh_gateway_service.control_plane import ControlPlane, resolve_control_plane
from hypermesh_gateway_service.inbox import ApprovalInbox, resolve_approval_inbox
from hypermesh_gateway_service.metrics import MeterQueue, resolve_meter_queue
from hypermesh_gateway_service.quota import ChatQuota, resolve_chat_quota
from hypermesh_gateway_service.receipts import ReceiptStore, resolve_receipt_store
from hypermesh_gateway_service.routes import (
    openai_router,
    refresh_known_tenants,
    router as hmg_router,
    seed_watched_tenants,
)
from hypermesh_gateway_service.tickets import TicketCache

logger = get_logger(__name__)

_OPENAPI_DESCRIPTION = (
    "Hypermesh / Hyperme.sh Fyber gateway. Proxies renter chat to a leased "
    "instance over the standing WireGuard peer. Chat requires a locally "
    "verified portal JWT or a renter API key, plus a paid active ticket. "
    "After the ticket is issued, chat does not call Panopticon or Keycloak. "
    "Opt-in IR door at /v1/ir/chat/completions classifies a small set "
    "(versioned taxonomy pack, not a detector) and holds a customer receipt "
    "on this door. A classify hold files /api/v1/aiuditor/approvals when "
    "AIUDITOR_SERVICE_URL is set; retry resumes or denies from that inbox. "
    "Org policy can allow, hold, or deny by purpose and class. "
    "Default renter chat does not classify unless the org opts in. "
    "Host addresses are not published here. Test chat: https://chat.test.hyperme.sh"
)


def create_app(
    *,
    control_plane: ControlPlane | None = None,
    gateway_service_secret: str | None = None,
    service_name: str | None = None,
    receipt_store: ReceiptStore | None = None,
    receipt_persist_path: str | None = None,
    meter_queue: MeterQueue | None = None,
    meter_persist_path: str | None = None,
    chat_quota: ChatQuota | None = None,
    classifier: Classifier | None = None,
    approval_inbox: ApprovalInbox | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging()
        app.state.control_plane = resolve_control_plane(control_plane)
        app.state.ticket_cache = TicketCache()
        seed_watched_tenants(app.state.ticket_cache)
        app.state.receipt_store = receipt_store or resolve_receipt_store(receipt_persist_path)
        app.state.meter_queue = meter_queue or resolve_meter_queue(meter_persist_path)
        app.state.chat_quota = chat_quota or resolve_chat_quota()
        app.state.classifier = classifier or resolve_classifier()
        app.state.approval_inbox = resolve_approval_inbox(approval_inbox)
        if gateway_service_secret is not None:
            app.state.gateway_service_secret = gateway_service_secret
        refresh_s = float(os.environ.get("HYPERMESH_ASSIGNMENT_REFRESH_S", "30"))
        stop = asyncio.Event()

        async def _refresh_loop() -> None:
            if refresh_s <= 0:
                return
            while not stop.is_set():
                await refresh_known_tenants(
                    app.state.control_plane,
                    app.state.ticket_cache,
                    app.state.meter_queue,
                )
                try:
                    await asyncio.wait_for(stop.wait(), timeout=refresh_s)
                    return
                except asyncio.TimeoutError:
                    continue

        task = asyncio.create_task(_refresh_loop())
        try:
            yield
        finally:
            stop.set()
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    app = FastAPI(
        lifespan=lifespan,
        title="Panopticon Hypermesh Router",
        description=_OPENAPI_DESCRIPTION,
        version="0.1.0",
    )

    @app.exception_handler(DoorError)
    async def _door_error(request: Request, exc: DoorError) -> JSONResponse:
        if request.url.path.startswith("/v1/"):
            return JSONResponse(
                status_code=exc.status_code,
                content=openai_error_body(exc.message, exc.code),
            )
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException) -> JSONResponse:
        if request.url.path.startswith("/v1/") and exc.status_code == 401:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=openai_error_body(INVALID_API_KEY_MESSAGE, "invalid_api_key"),
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )

    @app.exception_handler(UnauthorizedException)
    async def _unauthorized(_: Request, ex: UnauthorizedException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": ex.message},
        )

    @app.exception_handler(ForbiddenException)
    async def _forbidden(_: Request, ex: ForbiddenException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": ex.message},
        )

    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema
        from fastapi.openapi.utils import get_openapi

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description or "",
            routes=app.routes,
        )
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi

    app.include_router(health_router, prefix="/api/v1")
    app.include_router(version_router)
    app.include_router(hmg_router, prefix="/api/v1")
    app.include_router(openai_router)
    add_optional_service_cors(
        app,
        env_var="HYPERMESH_GATEWAY_CORS_ORIGINS",
        default_origins=(
            "https://hyperme.sh,https://www.hyperme.sh,https://test.hyperme.sh,"
            "https://chat.test.hyperme.sh,http://localhost:3000,http://127.0.0.1:3000,"
            "http://localhost:5173,http://127.0.0.1:5173"
        ),
    )
    logger.info(
        "Hypermesh gateway: health + /api/v1/hypermesh-gateway + /v1/chat/completions + /v1/ir"
    )
    from controlplane_api.metrics import install_http_metrics

    install_http_metrics(app)
    return app


app = create_app()
