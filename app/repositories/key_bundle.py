from sqlalchemy import func, select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session

from app.logger import logger
from app.models.key_bundle import OneTimePreKey, UserKeyBundle
from app.models.user import User


class SQLKeyBundleRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def store_key_bundle(
        self,
        user_id: int,
        identity_pub: bytes,
        signed_prekey_pub: bytes,
        signed_prekey_sig: bytes,
        pq_prekey_pub: bytes,
        pq_prekey_sig: bytes,
    ) -> None:
        self._session.execute(
            insert(UserKeyBundle)
            .values(
                user_id=user_id,
                identity_pub=identity_pub,
                signed_prekey_pub=signed_prekey_pub,
                signed_prekey_sig=signed_prekey_sig,
                pq_prekey_pub=pq_prekey_pub,
                pq_prekey_sig=pq_prekey_sig,
            )
            .on_conflict_do_update(
                index_elements=["user_id"],
                set_={
                    "identity_pub": identity_pub,
                    "signed_prekey_pub": signed_prekey_pub,
                    "signed_prekey_sig": signed_prekey_sig,
                    "pq_prekey_pub": pq_prekey_pub,
                    "pq_prekey_sig": pq_prekey_sig,
                    "updated_at": func.strftime("%s", "now"),
                },
            )
        )
        self._session.commit()
        logger.info("stored key bundle user_id=%d", user_id)

    def get_key_bundle(self, user_id: int) -> UserKeyBundle | None:
        bundle = self._session.scalar(
            select(UserKeyBundle).where(UserKeyBundle.user_id == user_id)
        )
        if bundle is None:
            logger.debug("key bundle not found user_id=%d", user_id)
        return bundle

    def add_one_time_prekeys(self, user_id: int, prekeys: list[bytes]) -> None:
        self._session.add_all(
            OneTimePreKey(user_id=user_id, prekey_pub=pk) for pk in prekeys
        )
        self._session.commit()
        logger.info("added %d one-time prekeys user_id=%d", len(prekeys), user_id)

    def pop_one_time_prekey(self, user_id: int) -> bytes | None:
        key: OneTimePreKey | None = self._session.scalars(
            select(OneTimePreKey).where(OneTimePreKey.user_id == user_id).order_by(OneTimePreKey.id).limit(1)
        ).first()
        if key is None:
            logger.warning("no one-time prekeys available user_id=%d", user_id)
            return None
        self._session.delete(key)
        self._session.commit()
        logger.debug("popped one-time prekey user_id=%d", user_id)
        return bytes(key.prekey_pub)

    def count_one_time_prekeys(self, user_id: int) -> int:
        count = self._session.scalar(
            select(func.count()).select_from(OneTimePreKey).where(OneTimePreKey.user_id == user_id)
        ) or 0
        logger.debug("one-time prekey count=%d user_id=%d", count, user_id)
        return count

    def get_identity_pub_by_username(self, username: str) -> tuple[int, bytes] | None:
        row = self._session.execute(
            select(User.id, UserKeyBundle.identity_pub)
            .join(UserKeyBundle, UserKeyBundle.user_id == User.id)
            .where(User.username == username)
        ).first()
        if row is None:
            logger.debug("identity_pub lookup by username: not found username=%s", username)
            return None
        logger.debug("identity_pub lookup by username: user_id=%d", row[0])
        return row[0], bytes(row[1])


