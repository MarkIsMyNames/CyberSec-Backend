from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends
from sqlalchemy.orm import Session

from app.session import _make_engine
from app.repositories.group import SQLGroupRepository
from app.repositories.key_bundle import SQLKeyBundleRepository
from app.repositories.message import SQLMessageRepository
from app.repositories.user import SQLUserRepository


def get_session() -> Generator[Session, None, None]:
    with Session(_make_engine(), expire_on_commit=False) as session:
        yield session # Yields the session to the caller


def get_user_repo(session: Session = Depends(get_session)) -> SQLUserRepository:
    return SQLUserRepository(session)


def get_key_bundle_repo(session: Session = Depends(get_session)) -> SQLKeyBundleRepository:
    return SQLKeyBundleRepository(session)


def get_message_repo(session: Session = Depends(get_session)) -> SQLMessageRepository:
    return SQLMessageRepository(session)


def get_group_repo(session: Session = Depends(get_session)) -> SQLGroupRepository:
    return SQLGroupRepository(session)
