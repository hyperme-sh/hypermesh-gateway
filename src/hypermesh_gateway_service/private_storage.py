"""Private payload stores must never emit SQL parameters or debug result rows."""
import logging
from sqlalchemy.ext.asyncio import create_async_engine
from controlplane_db.session import normalize_database_url


def private_engine(url: str, name: str):
    # hide_parameters does not hide SQLAlchemy's DEBUG result-row logging.
    # Give private engines a non-propagating logger, even when the parent SQL
    # logger is DEBUG. Availability failures use the app's payload-free logs.
    logger=logging.getLogger(f'sqlalchemy.engine.Engine.{name}')
    logger.setLevel(logging.WARNING)
    logger.propagate=False
    if not any(isinstance(handler,logging.NullHandler) for handler in logger.handlers):
        logger.addHandler(logging.NullHandler())
    return create_async_engine(normalize_database_url(url),echo=False,
        hide_parameters=True,logging_name=name)
