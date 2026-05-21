from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from fastapi import Depends
from sqlalchemy.orm import Session

from app.session import _make_engine


@contextmanager
def open_session() -> Generator[Session, None, None]:
    with Session(_make_engine(), expire_on_commit=False) as session:
        yield session


def get_session() -> Generator[Session, None, None]:
    with open_session() as session:
        yield session


def repo_dep(cls):
    return lambda session=Depends(get_session): cls(session)
