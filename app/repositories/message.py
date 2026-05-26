from typing import Literal

from sqlalchemy import delete, func, insert, literal, select
from sqlalchemy.orm import Session

from app.config import config
from app.logger import logger
from app.models.message import Message


class SQLMessageRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def store_message(
        self,
        sender_id: int,
        recipient_id: int,
        ciphertext: bytes,
        ratchet_header_enc: bytes,
    ) -> int:
        max_msgs: int = config["messaging"]["inbox_max_messages"]
        msg_id = self._session.execute(
            insert(Message)
            .from_select(
                [
                    Message.sender_id,
                    Message.recipient_id,
                    Message.ciphertext,
                    Message.ratchet_header_enc,
                ],
                select(
                    literal(sender_id),
                    literal(recipient_id),
                    literal(ciphertext),
                    literal(ratchet_header_enc),
                ).where(
                    select(func.count())
                    .select_from(Message)
                    .where(Message.recipient_id == recipient_id)
                    .scalar_subquery()
                    < max_msgs
                ),
            )
            .returning(Message.id)
        ).scalar()
        if msg_id is None:
            logger.warning(
                "store_message rejected — inbox full recipient_id=%d", recipient_id
            )
            raise OverflowError("inbox full recipient_id=%d" % recipient_id)
        self._session.commit()
        logger.info(
            "stored message id=%d sender_id=%d recipient_id=%d",
            msg_id,
            sender_id,
            recipient_id,
        )
        return msg_id

    def get_messages_for_user(
        self, user_id: int, limit: int, offset: int
    ) -> list[Message]:
        messages = list(
            self._session.scalars(
                select(Message)
                .where(Message.recipient_id == user_id)
                .order_by(Message.id)
                .limit(limit)
                .offset(offset)
            )
        )
        logger.debug("fetched %d messages user_id=%d", len(messages), user_id)
        return messages

    def delete_message(
        self,
        message_id: int,
        owner_field: Literal["sender_id", "recipient_id"],
        user_id: int,
    ) -> bool:
        owner_column = (
            Message.sender_id if owner_field == "sender_id" else Message.recipient_id
        )
        deleted = (
            self._session.execute(
                delete(Message)
                .where(Message.id == message_id, owner_column == user_id)
                .returning(Message.id)
            ).scalar()
            is not None
        )
        self._session.commit()
        return deleted
