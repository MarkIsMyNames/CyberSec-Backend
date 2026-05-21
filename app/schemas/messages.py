import base64

from pydantic import BaseModel

from app.schemas.common import Base64


class SendMessageRequest(BaseModel):
    recipient_id: int
    ciphertext: Base64
    ratchet_header_enc: Base64

    def ciphertext_bytes(self) -> bytes:
        return base64.b64decode(self.ciphertext)

    def ratchet_header_enc_bytes(self) -> bytes:
        return base64.b64decode(self.ratchet_header_enc)


class MessageResponse(BaseModel):
    id: int
    ciphertext: str
    ratchet_header_enc: str
    sent_at: int
    revocation_token: str | None = None # To revoke access to a message


class RevokeRequest(BaseModel):
    revocation_token: Base64

    def token_bytes(self) -> bytes:
        return base64.b64decode(self.revocation_token)
