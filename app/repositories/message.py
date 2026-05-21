import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.logger import logger
from app.models.message import Message


class SQLMessageRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def store_message(
        self,
        recipient_id: int,
        ciphertext: bytes,
        ratchet_header_enc: bytes,
        revocation_token_hash: bytes,
    ) -> Message:
        msg = Message(
            recipient_id=recipient_id,
            ciphertext=ciphertext,
            ratchet_header_enc=ratchet_header_enc,
            revocation_token_hash=revocation_token_hash,
        )
        self._session.add(msg)
        self._session.commit()
        self._session.refresh(msg)
        logger.info("stored message id=%d recipient_id=%d", msg.id, recipient_id)
        return msg

    def get_messages_for_user(self, user_id: int) -> list[Message]:
        messages = list(self._session.scalars(
            select(Message).where(Message.recipient_id == user_id).order_by(Message.sent_at)
        ))
        logger.debug("fetched %d messages user_id=%d", len(messages), user_id)
        return messages

    def record_receipt(self, message_id: int, user_id: int) -> bool:
        msg: Message | None = self._session.scalar(
            select(Message).where(Message.id == message_id, Message.recipient_id == user_id)
        )
        if msg is None:
            return False
        self._session.delete(msg)
        self._session.commit()
        logger.info(
            "receipt recorded and message deleted message_id=%d user_id=%d",
            message_id,
            user_id,
        )
        return True

    def revoke_message(self, message_id: int, raw_token: bytes) -> bool:
        msg: Message | None = self._session.scalar(select(Message).where(Message.id == message_id))
        if msg is None:
            logger.warning(
                "revoke failed — message not found message_id=%d", message_id
            )
            return False
        if hashlib.sha256(raw_token).digest() != msg.revocation_token_hash:
            logger.warning("revoke failed — invalid token message_id=%d", message_id)
            return False
        self._session.delete(msg)
        self._session.commit()
        logger.info("message revoked message_id=%d", message_id)
        return True
