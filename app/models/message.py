from __future__ import annotations

import time

from sqlalchemy import ForeignKey, Index, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (Index("ix_messages_recipient_id_sent_at", "recipient_id", "sent_at"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ratchet_header_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    revocation_token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sent_at: Mapped[int] = mapped_column(default=time.time)


