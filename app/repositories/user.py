from sqlalchemy import select
from sqlalchemy.orm import Session

from app.logger import logger
from app.models.user import RefreshTokenBlocklist, User


class SQLUserRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_user(
        self, username: str, srp_salt: str, srp_verifier: str, totp_secret_enc: bytes
    ) -> User:
        user = User(
            username=username,
            srp_salt=srp_salt,
            srp_verifier=srp_verifier,
            totp_secret_enc=totp_secret_enc,
        )
        self._session.add(user)
        self._session.commit()
        self._session.refresh(user)
        logger.info("created user id=%d username=%s", user.id, username)
        return user

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
        blocked = self._session.get(RefreshTokenBlocklist, jti_hash) is not None
        if blocked:
            logger.warning("blocked refresh token presented")
        return blocked
