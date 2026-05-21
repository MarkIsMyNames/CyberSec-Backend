import hashlib
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.logger import logger
from app.models.group import (
    Group,
    GroupMember,
    GroupMessage,
    GroupMessageReceipt,
    SenderKeyDistribution,
)


class SQLGroupRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_group(self, name: str, creator_id: int) -> Group:
        group = Group(name=name, creator_id=creator_id)
        self._session.add(group)
        self._session.flush()
        self._session.add(GroupMember(group_id=group.id, user_id=creator_id))
        self._session.commit()
        self._session.refresh(group)
        logger.info(
            "created group id=%d name=%s creator_id=%d", group.id, name, creator_id
        )
        return group

    def get_group(self, group_id: int) -> Group | None:
        group = self._session.get(Group, group_id)
        if group is None:
            logger.debug("group not found group_id=%d", group_id)
        return group

    def is_creator(self, group_id: int, user_id: int) -> bool:
        group = self._session.get(Group, group_id)
        return group is not None and group.creator_id == user_id

    def add_member(self, group_id: int, requester_id: int, user_id: int) -> None:
        if not self.is_creator(group_id, requester_id):
            logger.warning(
                "unauthorised add_member group_id=%d requester_id=%d",
                group_id,
                requester_id,
            )
            raise PermissionError("only the group creator can add members")
        if not self._session.get(GroupMember, (group_id, user_id)):
            self._session.add(GroupMember(group_id=group_id, user_id=user_id))
            self._session.commit()
            logger.info("added member group_id=%d user_id=%d", group_id, user_id)

    def remove_member(self, group_id: int, requester_id: int, user_id: int) -> None:
        if not self.is_creator(group_id, requester_id):
            logger.warning(
                "unauthorised remove_member group_id=%d requester_id=%d",
                group_id,
                requester_id,
            )
            raise PermissionError("only the group creator can remove members")
        member = self._session.get(GroupMember, (group_id, user_id))
        if member:
            self._session.delete(member)
            self._session.commit()
            logger.info("removed member group_id=%d user_id=%d", group_id, user_id)

    def get_members(self, group_id: int) -> list[int]:
        rows = (
            self._session.query(GroupMember)
            .filter_by(group_id=group_id)
            .order_by(GroupMember.user_id)
            .all()
        )
        logger.debug("fetched %d members group_id=%d", len(rows), group_id)
        return [r.user_id for r in rows]

    def is_member(self, group_id: int, user_id: int) -> bool:
        return self._session.get(GroupMember, (group_id, user_id)) is not None

    def store_skdm(
        self, group_id: int, recipient_id: int, skdm_ciphertext: bytes
    ) -> None:
        self._session.add(
            SenderKeyDistribution(
                group_id=group_id,
                recipient_id=recipient_id,
                skdm_ciphertext=skdm_ciphertext,
            )
        )
        self._session.commit()
        logger.info("stored SKDM group_id=%d recipient_id=%d", group_id, recipient_id)

    def get_skdms_for_user(self, user_id: int, group_id: int) -> list[bytes]:
        rows = (
            self._session.query(SenderKeyDistribution)
            .filter_by(recipient_id=user_id, group_id=group_id)
            .order_by(SenderKeyDistribution.created_at)
            .all()
        )
        logger.debug(
            "fetched %d SKDMs user_id=%d group_id=%d", len(rows), user_id, group_id
        )
        return [r.skdm_ciphertext for r in rows]

    def store_group_message(
        self, group_id: int, ciphertext: bytes, revocation_token_hash: bytes
    ) -> GroupMessage:
        msg = GroupMessage(
            group_id=group_id,
            ciphertext=ciphertext,
            revocation_token_hash=revocation_token_hash,
        )
        self._session.add(msg)
        self._session.flush()
        members = self._session.query(GroupMember).filter_by(group_id=group_id).all()
        self._session.add_all(
            GroupMessageReceipt(message_id=msg.id, user_id=m.user_id) for m in members
        )
        self._session.commit()
        self._session.refresh(msg)
        logger.info(
            "stored group message id=%d group_id=%d recipients=%d",
            msg.id,
            group_id,
            len(members),
        )
        return msg

    def get_group_messages(self, group_id: int) -> list[GroupMessage]:
        messages = (
            self._session.query(GroupMessage)
            .filter_by(group_id=group_id)
            .order_by(GroupMessage.sent_at)
            .all()
        )
        logger.debug("fetched %d group messages group_id=%d", len(messages), group_id)
        return messages

    def revoke_group_message(self, message_id: int, raw_token: bytes) -> bool:
        msg = self._session.get(GroupMessage, message_id)
        if msg is None:
            logger.warning(
                "group message revoke failed — not found message_id=%d", message_id
            )
            return False
        if hashlib.sha256(raw_token).digest() != msg.revocation_token_hash:
            logger.warning(
                "group message revoke failed — invalid token message_id=%d", message_id
            )
            return False
        self._session.delete(msg)
        self._session.commit()
        logger.info("group message revoked message_id=%d", message_id)
        return True

    def record_group_receipt(self, message_id: int, user_id: int) -> bool:
        receipt = self._session.get(GroupMessageReceipt, (message_id, user_id))
        if receipt:
            self._session.delete(receipt)
            self._session.flush()
        remaining: int = (
            self._session.scalar(
                select(func.count()).where(GroupMessageReceipt.message_id == message_id)
            )
            or 0
        )
        if remaining == 0:
            msg = self._session.get(GroupMessage, message_id)
            if msg:
                self._session.delete(msg)
            logger.info(
                "group message deleted — all receipts acknowledged message_id=%d",
                message_id,
            )
        else:
            logger.debug(
                "group receipt recorded message_id=%d user_id=%d remaining=%d",
                message_id,
                user_id,
                remaining,
            )
        self._session.commit()
        return remaining == 0
