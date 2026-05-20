from __future__ import annotations

from typing import cast

from sqlalchemy import func
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session

from app.logger import logger
from app.models.key_bundle import IdentityKey, OneTimePreKey, PQPreKey


class SQLKeyBundleRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def store_identity_key(
        self,
        user_id: int,
        identity_pub: bytes,
        signed_prekey_pub: bytes,
        signed_prekey_sig: bytes,
    ) -> None:
        self._session.execute(
            insert(IdentityKey)
            .values(
                user_id=user_id,
                identity_pub=identity_pub,
                signed_prekey_pub=signed_prekey_pub,
                signed_prekey_sig=signed_prekey_sig,
            )
            .on_conflict_do_update(
                index_elements=["user_id"],
                set_={
                    "identity_pub": identity_pub,
                    "signed_prekey_pub": signed_prekey_pub,
                    "signed_prekey_sig": signed_prekey_sig,
                    "updated_at": func.strftime("%s", "now"),
                },
            )
        )
        self._session.commit()
        logger.info("stored identity key user_id=%d", user_id)

    def get_identity_key(self, user_id: int) -> type[IdentityKey] | None:
        key = self._session.get(IdentityKey, user_id)
        if key is None:
            logger.debug("identity key not found user_id=%d", user_id)
        return key

    def add_one_time_prekeys(self, user_id: int, prekeys: list[bytes]) -> None:
        self._session.add_all(
            OneTimePreKey(user_id=user_id, prekey_pub=pk) for pk in prekeys
        )
        self._session.commit()
        logger.info("added %d one-time prekeys user_id=%d", len(prekeys), user_id)

    def pop_one_time_prekey(self, user_id: int) -> bytes | None:
        key = (
            self._session.query(OneTimePreKey)
            .filter_by(user_id=user_id)
            .order_by(OneTimePreKey.id)
            .first()
        )
        if key is None:
            logger.warning("no one-time prekeys available user_id=%d", user_id)
            return None
        self._session.delete(key)
        self._session.commit()
        logger.debug("popped one-time prekey user_id=%d", user_id)
        return cast(bytes, cast(object, key.prekey_pub))

    def count_one_time_prekeys(self, user_id: int) -> int:
        count = self._session.query(OneTimePreKey).filter_by(user_id=user_id).count()
        logger.debug("one-time prekey count=%d user_id=%d", count, user_id)
        return count

    def store_pq_prekey(
        self, user_id: int, pq_prekey_pub: bytes, pq_prekey_sig: bytes
    ) -> None:
        self._session.execute(
            insert(PQPreKey)
            .values(
                user_id=user_id,
                pq_prekey_pub=pq_prekey_pub,
                pq_prekey_sig=pq_prekey_sig,
            )
            .on_conflict_do_update(
                index_elements=["user_id"],
                set_={
                    "pq_prekey_pub": pq_prekey_pub,
                    "pq_prekey_sig": pq_prekey_sig,
                    "updated_at": func.strftime("%s", "now"),
                },
            )
        )
        self._session.commit()
        logger.info("stored PQ prekey user_id=%d", user_id)

    def get_pq_prekey(self, user_id: int) -> type[PQPreKey] | None:
        key = self._session.get(PQPreKey, user_id)
        if key is None:
            logger.debug("PQ prekey not found user_id=%d", user_id)
        return key
