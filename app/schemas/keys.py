from __future__ import annotations

import base64

from pydantic import BaseModel


class KeyBundleUpload(BaseModel):
    identity_pub: str
    signed_prekey_pub: str
    signed_prekey_sig: str
    one_time_prekeys: list[str]
    pq_prekey_pub: str
    pq_prekey_sig: str

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
    one_time_prekeys: list[str]

    def prekeys_bytes(self) -> list[bytes]:
        return [base64.b64decode(key) for key in self.one_time_prekeys]


class KeyBundleResponse(BaseModel):
    user_id: int
    identity_pub: str
    signed_prekey_pub: str
    signed_prekey_sig: str
    one_time_prekey: str | None
    pq_prekey_pub: str
    pq_prekey_sig: str
