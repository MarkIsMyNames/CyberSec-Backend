from sqlalchemy import case, delete, func, insert, select, update
from sqlalchemy.orm import Session

from app.logger import logger
from app.models.group import Group, GroupMember
from app.models.user import RefreshTokenBlocklist, User


class SQLUserRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_user(
        self,
        username: str,
        srp_salt: str,
        srp_verifier_enc: bytes,
        totp_secret_enc: bytes,
    ) -> int:
        user_id: int = self._session.execute(
            insert(User)
            .values(
                username=username,
                srp_salt=srp_salt,
                srp_verifier_enc=srp_verifier_enc,
                totp_secret_enc=totp_secret_enc,
            )
            .returning(User.id)
        ).scalar_one()
        self._session.commit()
        logger.info("created user id=%d username=%s", user_id, username)
        return user_id

    def get_user_by_username(self, username: str) -> User | None:
        user = self._session.scalar(select(User).where(User.username == username))
        if user is None:
            logger.debug("user not found username=%s", username)
        return user

    def get_user_by_id(self, user_id: int) -> User | None:
        user = self._session.scalar(select(User).where(User.id == user_id))
        if user is None:
            logger.debug("user not found id=%d", user_id)
        return user

    def block_refresh_token(self, jti_hash: bytes, expires_at: int) -> None:
        self._session.add(
            RefreshTokenBlocklist(jti_hash=jti_hash, expires_at=expires_at)
        )
        self._session.commit()
        logger.info("refresh token blocked expires_at=%d", expires_at)

    def is_refresh_token_blocked(self, jti_hash: bytes) -> bool:
        blocked = (
            self._session.scalar(
                select(RefreshTokenBlocklist).where(
                    RefreshTokenBlocklist.jti_hash == jti_hash
                )
            )
            is not None
        )
        if blocked:
            logger.warning("blocked refresh token presented")
        return blocked

    def delete_user(self, user_id: int) -> None:
        self._session.execute(select(User).where(User.id == user_id).with_for_update())
        rows = list(
            self._session.execute(
                select(
                    Group.id,
                    select(func.count())
                    .select_from(GroupMember)
                    .where(GroupMember.group_id == Group.id)
                    .scalar_subquery()
                    .label("member_count"),
                )
                .where(
                    Group.id.in_(
                        select(GroupMember.group_id).where(
                            GroupMember.user_id == user_id
                        )
                    )
                )
                .order_by(Group.id)
                .with_for_update()
            )
        )
        sole_member_ids = [r.id for r in rows if r.member_count <= 1]
        multi_member_ids = [r.id for r in rows if r.member_count > 1]

        if sole_member_ids:
            self._session.execute(delete(Group).where(Group.id.in_(sole_member_ids)))
            logger.info(
                "deleted sole-member groups user_id=%d group_ids=%s",
                user_id,
                sole_member_ids,
            )
        if multi_member_ids:
            new_creator_subq = (
                select(func.min(GroupMember.user_id))
                .where(
                    GroupMember.group_id == Group.id,
                    GroupMember.user_id != user_id,
                )
                .scalar_subquery()
            )
            self._session.execute(
                update(Group)
                .where(Group.id.in_(multi_member_ids))
                .values(
                    creator_id=case(
                        (Group.creator_id == user_id, new_creator_subq),
                        else_=Group.creator_id,
                    ),
                    epoch=Group.epoch + 1,
                )
            )
            logger.info(
                "bumped epoch and reassigned creator where needed user_id=%d group_ids=%s",
                user_id,
                multi_member_ids,
            )
        self._session.execute(delete(User).where(User.id == user_id))
        self._session.commit()
        logger.info(
            "deleted user id=%d sole_member_groups=%d multi_member_groups=%d",
            user_id,
            len(sole_member_ids),
            len(multi_member_ids),
        )
