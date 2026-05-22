from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import config
from app.logger import logger
from app.models.message import Message


class SQLMessageRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def inbox_count(self, user_id: int) -> int:
        return self._session.scalar(
            select(func.count()).select_from(Message).where(Message.recipient_id == user_id)
        ) or 0

    def store_message(
        self,
        sender_id: int,
        recipient_id: int,
        ciphertext: bytes,
        ratchet_header_enc: bytes,
    ) -> Message:
        msg = Message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            ciphertext=ciphertext,
            ratchet_header_enc=ratchet_header_enc,
        )
        self._session.add(msg)
        self._session.flush()
        if self.inbox_count(recipient_id) > config["messaging"]["inbox_max_messages"]:
            self._session.rollback()
            raise OverflowError("inbox full recipient_id=%d" % recipient_id)
        self._session.commit()
        self._session.refresh(msg)
        logger.info("stored message id=%d sender_id=%d recipient_id=%d", msg.id, sender_id, recipient_id)
        return msg

    def get_messages_for_user(self, user_id: int, limit: int, offset: int) -> list[Message]:
        messages = list(self._session.scalars(
            select(Message)
            .where(Message.recipient_id == user_id)
            .order_by(Message.id)
            .limit(limit)
            .offset(offset)
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

    def revoke_message(self, message_id: int, sender_id: int) -> bool:
        msg: Message | None = self._session.scalar(select(Message).where(Message.id == message_id))
        if msg is None:
            logger.warning("revoke failed — message not found message_id=%d", message_id)
            return False
        if msg.sender_id != sender_id:
            logger.warning(
                "revoke failed — not sender message_id=%d sender_id=%d requester_id=%d",
                message_id,
                msg.sender_id,
                sender_id,
            )
            return False
        self._session.delete(msg)
        self._session.commit()
        logger.info("message revoked message_id=%d sender_id=%d", message_id, sender_id)
        return True
