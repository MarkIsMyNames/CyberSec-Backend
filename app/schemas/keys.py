import base64

from pydantic import BaseModel

from app.schemas.common import Base64


class KeyBundleUpload(BaseModel):
    identity_pub: Base64
    signed_prekey_pub: Base64
    signed_prekey_sig: Base64
    one_time_prekeys: list[Base64]
    pq_prekey_pub: Base64
    pq_prekey_sig: Base64

    def identity_pub_bytes(self) -> bytes:
        return base64.b64decode(self.identity_pub)

    def signed_prekey_pub_bytes(self) -> bytes:
        return base64.b64decode(self.signed_prekey_pub)

    def signed_prekey_sig_bytes(self) -> bytes:
        return base64.b64decode(self.signed_prekey_sig)

    def one_time_prekeys_bytes(self) -> list[bytes]:
        return [base64.b64decode(k) for k in self.one_time_prekeys]

    def pq_prekey_pub_bytes(self) -> bytes:
        return base64.b64decode(self.pq_prekey_pub)

    def pq_prekey_sig_bytes(self) -> bytes:
        return base64.b64decode(self.pq_prekey_sig)


class UploadOneTimePreKeysRequest(BaseModel):
    one_time_prekeys: list[Base64]

    def prekeys_bytes(self) -> list[bytes]:
        return [base64.b64decode(key) for key in self.one_time_prekeys]


class OneTimePreKeyCountResponse(BaseModel):
    count: int


class KeyBundleResponse(BaseModel):
    identity_pub: str
    signed_prekey_pub: str
    signed_prekey_sig: str
    one_time_prekey: str | None
    pq_prekey_pub: str
    pq_prekey_sig: str


class UserIdentityResponse(BaseModel):
    user_id: int
    identity_pub: str
