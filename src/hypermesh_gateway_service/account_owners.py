"""Open retained data owners only under explicitly enabled retirement enforcement."""
from contextlib import asynccontextmanager
import asyncio
import os

from sqlalchemy.ext.asyncio import async_sessionmaker

from hypermesh_gateway_service.history import HistoryStore
from hypermesh_gateway_service.training import TrainingStore
from hypermesh_gateway_service.private_storage import private_engine


@asynccontextmanager
async def open_owners(state):
    engines = []
    state.history_store = state.training_store = None
    try:
        ledger = state.account_ledger
        if ledger is not None:
            for name, store in (("history", HistoryStore), ("training", TrainingStore)):
                url = os.environ.get(f"HYPERMESH_{name.upper()}_DATABASE_URL", "").strip()
                if url:
                    if not url.startswith(("postgresql://", "postgresql+asyncpg://")):
                        raise ValueError("Retained data requires PostgreSQL")
                    engine = private_engine(url, f"hypermesh_{name}")
                    engines.append(engine)
                    setattr(state, name + "_store", store(async_sessionmaker(engine, expire_on_commit=False), account_ledger=ledger))
                await asyncio.to_thread(ledger.configure_owner, name, bool(url),
                    never_configured=os.environ.get(f"HYPERMESH_ACCOUNT_{name.upper()}_NEVER_CONFIGURED", "").lower() == "true")
        yield
    finally:
        for engine in engines:
            await engine.dispose()
