from sqlalchemy import delete, exists, func, literal, select, update
from sqlalchemy.dialects.sqlite import insert
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

    def create_group(self, name: str, creator_id: int, initial_members: dict[int, bytes] | None = None) -> Group:
        group = Group(name=name, creator_id=creator_id, epoch=0)
        self._session.add(group)
        self._session.flush()
        self._session.add(GroupMember(group_id=group.id, user_id=creator_id))
        if initial_members:
            self._session.add_all(
                GroupMember(group_id=group.id, user_id=uid) for uid in initial_members
            )
            self._session.flush()
            self._store_skdms(group.id, initial_members)
        self._session.commit()
        self._session.refresh(group)
        logger.info(
            "created group id=%d name=%s creator_id=%d initial_members=%d",
            group.id, name, creator_id, len(initial_members) if initial_members else 0,
        )
        return group

    def get_group(self, group_id: int) -> Group | None:
        group: Group | None = self._session.scalar(select(Group).where(Group.id == group_id))
        if group is None:
            logger.debug("group not found group_id=%d", group_id)
        return group

    def is_creator(self, group_id: int, user_id: int) -> bool:
        return self._session.scalar(
            select(Group.creator_id).where(Group.id == group_id)
        ) == user_id

    def add_member(self, group_id: int, requester_id: int, user_id: int, skdm_ciphertext: bytes) -> None:
        if not self.is_creator(group_id, requester_id):
            logger.warning(
                "unauthorised add_member group_id=%d requester_id=%d",
                group_id,
                requester_id,
            )
            raise PermissionError("only the group creator can add members")
        self._session.execute(
            insert(GroupMember)
            .values(group_id=group_id, user_id=user_id)
            .on_conflict_do_nothing()
        )
        self._store_skdms(group_id, {user_id: skdm_ciphertext})
        self._session.commit()
        logger.info("added member group_id=%d user_id=%d", group_id, user_id)

    def remove_member(self, group_id: int, requester_id: int, user_id: int, skdm_ciphertexts: dict[int, bytes] | None = None) -> None:
        is_self = requester_id == user_id
        if not is_self and not self.is_creator(group_id, requester_id):
            logger.warning(
                "unauthorised remove_member group_id=%d requester_id=%d target_id=%d",
                group_id,
                requester_id,
                user_id,
            )
            raise PermissionError("only the group creator can remove other members")

        deleted = self._session.execute(
            delete(GroupMember).where(
                GroupMember.group_id == group_id, GroupMember.user_id == user_id
            )
        ).rowcount
        if deleted == 0:
            logger.debug("remove_member no-op: user not in group group_id=%d user_id=%d", group_id, user_id)
            return

        self._session.execute(
            delete(Group).where(
                Group.id == group_id,
                select(func.count()).select_from(GroupMember).where(GroupMember.group_id == group_id).scalar_subquery() <= 1,
            )
        )
        current_creator_id = self._session.scalar(
            select(Group.creator_id).where(Group.id == group_id)
        )
        if current_creator_id is None:
            self._session.commit()
            logger.info("Group %d no longer exists", group_id)
            return

        if current_creator_id == user_id:
            new_creator: GroupMember | None = self._session.scalar(
                select(GroupMember)
                .where(GroupMember.group_id == group_id)
                .order_by(GroupMember.user_id)
                .limit(1)
            )
            if new_creator is None:
                self._session.execute(delete(Group).where(Group.id == group_id))
                logger.info("group deleted — creator left with no remaining members group_id=%d", group_id)
                self._session.commit()
                return
            self._session.execute(
                update(Group).where(Group.id == group_id).values(creator_id=new_creator.user_id)
            )
            logger.info(
                "group creator reassigned group_id=%d new_creator_id=%d",
                group_id,
                new_creator.user_id,
            )

        self._session.execute(
            delete(SenderKeyDistribution).where(SenderKeyDistribution.group_id == group_id)
        )
        if skdm_ciphertexts:
            self._store_skdms(group_id, skdm_ciphertexts)
        else:
            self._session.execute(
                update(Group).where(Group.id == group_id).values(epoch=Group.epoch + 1)
            )
        logger.info("removed member group_id=%d user_id=%d", group_id, user_id)
        self._session.commit()

    def get_groups_for_user(self, user_id: int) -> list[Group]:
        rows = list(self._session.scalars(
            select(Group)
            .join(GroupMember, GroupMember.group_id == Group.id)
            .where(GroupMember.user_id == user_id)
            .order_by(Group.id)
        ))
        logger.debug("fetched %d groups user_id=%d", len(rows), user_id)
        return rows

    def get_members(self, group_id: int) -> list[int]:
        rows = list(self._session.scalars(
            select(GroupMember).where(GroupMember.group_id == group_id).order_by(GroupMember.user_id)
        ))
        logger.debug("fetched %d members group_id=%d", len(rows), group_id)
        return [r.user_id for r in rows]

    def is_member(self, group_id: int, user_id: int) -> bool:
        return self._session.scalar(
            select(GroupMember).where(GroupMember.group_id == group_id, GroupMember.user_id == user_id)
        ) is not None

    def store_skdms(self, group_id: int, skdm_ciphertexts: dict[int, bytes]) -> None:
        self._store_skdms(group_id, skdm_ciphertexts)
        self._session.commit()

    def _store_skdms(self, group_id: int, skdm_ciphertexts: dict[int, bytes]) -> None:
        epoch: int | None = self._session.scalar(
            update(Group)
            .where(Group.id == group_id)
            .values(epoch=Group.epoch + 1)
            .returning(Group.epoch)
        )
        if epoch is None:
            logger.warning("store_skdms failed — group not found group_id=%d", group_id)
            raise ValueError("group %d does not exist" % group_id)
        self._session.add_all(
            SenderKeyDistribution(
                group_id=group_id,
                recipient_id=recipient_id,
                skdm_ciphertext=ciphertext,
                epoch=epoch,
            )
            for recipient_id, ciphertext in skdm_ciphertexts.items()
        )
        logger.info("stored %d SKDMs group_id=%d epoch=%d", len(skdm_ciphertexts), group_id, epoch)

    def pop_skdms_for_user(self, user_id: int, group_id: int) -> list[tuple[int, bytes]]:
        rows = self._session.execute(
            delete(SenderKeyDistribution)
            .where(SenderKeyDistribution.recipient_id == user_id, SenderKeyDistribution.group_id == group_id)
            .returning(SenderKeyDistribution.epoch, SenderKeyDistribution.skdm_ciphertext)
        ).all()
        self._session.commit()
        if not rows:
            return []
        logger.info("popped %d SKDMs user_id=%d group_id=%d", len(rows), user_id, group_id)
        return [(r.epoch, bytes(r.skdm_ciphertext)) for r in rows]

    def store_group_message(
        self, group_id: int, sender_id: int, epoch: int, ciphertext: bytes
    ) -> GroupMessage:
        msg = GroupMessage(
            group_id=group_id,
            sender_id=sender_id,
            epoch=epoch,
            ciphertext=ciphertext,
        )
        self._session.add(msg)
        self._session.flush()
        self._session.execute(
            insert(GroupMessageReceipt).from_select(
                [GroupMessageReceipt.message_id, GroupMessageReceipt.user_id],
                select(literal(msg.id), GroupMember.user_id)
                .where(GroupMember.group_id == group_id, GroupMember.user_id != sender_id),
            )
        )
        self._session.commit()
        self._session.refresh(msg)
        logger.info(
            "stored group message id=%d group_id=%d sender_id=%d",
            msg.id,
            group_id,
            sender_id,
        )
        return msg

    def get_group_messages(self, group_id: int, user_id: int) -> list[GroupMessage]:
        messages = list(self._session.scalars(
            select(GroupMessage)
            .join(GroupMessageReceipt, (GroupMessageReceipt.message_id == GroupMessage.id) & (GroupMessageReceipt.user_id == user_id))
            .where(GroupMessage.group_id == group_id)
            .order_by(GroupMessage.id)
        ))
        logger.debug("fetched %d group messages group_id=%d user_id=%d", len(messages), group_id, user_id)
        return messages

    def revoke_group_message(self, message_id: int, sender_id: int) -> bool:
        deleted = self._session.execute(
            delete(GroupMessage).where(GroupMessage.id == message_id, GroupMessage.sender_id == sender_id)
        ).rowcount
        if deleted == 0:
            logger.warning("group message revoke failed message_id=%d requester_id=%d", message_id, sender_id)
            return False
        self._session.commit()
        logger.info("group message revoked message_id=%d sender_id=%d", message_id, sender_id)
        return True

    def record_group_receipt(self, message_id: int, user_id: int) -> None:
        self._session.execute(
            delete(GroupMessageReceipt).where(
                GroupMessageReceipt.message_id == message_id,
                GroupMessageReceipt.user_id == user_id,
            )
        )
        self._session.execute(
            delete(GroupMessage).where(
                GroupMessage.id == message_id,
                ~exists(
                    select(GroupMessageReceipt.message_id)
                    .where(GroupMessageReceipt.message_id == message_id)
                ),
            )
        )
        self._session.commit()
        logger.debug("group receipt recorded message_id=%d user_id=%d", message_id, user_id)
