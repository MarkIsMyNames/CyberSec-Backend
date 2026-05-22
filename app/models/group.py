import time

from sqlalchemy import ForeignKey, Index, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    creator_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    epoch: Mapped[int] = mapped_column(default=0, nullable=False)
    created_at: Mapped[int] = mapped_column(default=time.time)


class GroupMember(Base):
    __tablename__ = "group_members"

    group_id: Mapped[int] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )


class SenderKeyDistribution(Base):
    __tablename__ = "sender_key_distributions"
    __table_args__ = (
        UniqueConstraint("recipient_id", "group_id", "epoch", name="uq_skd_recipient_group_epoch"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    group_id: Mapped[int] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), nullable=False
    )
    recipient_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    skdm_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    epoch: Mapped[int] = mapped_column(nullable=False)


class GroupMessage(Base):
    __tablename__ = "group_messages"
    __table_args__ = (
        Index("ix_group_messages_group_id_sent_at", "group_id", "sent_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    sender_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    group_id: Mapped[int] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), nullable=False
    )
    epoch: Mapped[int] = mapped_column(nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sent_at: Mapped[int] = mapped_column(default=time.time)


class GroupMessageReceipt(Base):
    __tablename__ = "group_message_receipts"

    message_id: Mapped[int] = mapped_column(
        ForeignKey("group_messages.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
