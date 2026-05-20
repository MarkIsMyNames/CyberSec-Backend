from __future__ import annotations

import time

from sqlalchemy import ForeignKey, Index, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class IdentityKey(Base):
    __tablename__ = "identity_keys"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    identity_pub: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signed_prekey_pub: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signed_prekey_sig: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[int] = mapped_column(default=time.time)


class OneTimePreKey(Base):
    __tablename__ = "one_time_prekeys"
    __table_args__ = (Index("ix_one_time_prekeys_user_id_id", "user_id", "id"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    prekey_pub: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[int] = mapped_column(default=time.time)


class PQPreKey(Base):
    __tablename__ = "pq_prekeys"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    pq_prekey_pub: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    pq_prekey_sig: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[int] = mapped_column(default=time.time)
