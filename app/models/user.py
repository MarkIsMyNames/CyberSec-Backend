from sqlalchemy import BigInteger, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class RefreshTokenBlocklist(Base):
    __tablename__ = "refresh_token_blocklist"

    jti_hash: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    srp_salt: Mapped[str] = mapped_column(String, nullable=False)
    srp_verifier_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    totp_secret_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
