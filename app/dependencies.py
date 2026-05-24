from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import TypeVar

from fastapi import Depends
from sqlalchemy.orm import Session

from app.session import get_engine

T = TypeVar("T")


@contextmanager
def open_session() -> Generator[Session, None, None]:
    with Session(get_engine(), expire_on_commit=False) as session:
        yield session


def get_session() -> Generator[Session, None, None]:
    with open_session() as session:
        yield session


def repo_dep(cls: Callable[[Session], T]) -> Callable[[Session], T]:
    def dep(session: Session = Depends(get_session)) -> T:
        return cls(session)

    return dep
