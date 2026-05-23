import base64
from typing import Annotated

from pydantic import AfterValidator, BaseModel

from app.config import config
from app.schemas.common import Base64


def _validate_ciphertext_size(value: str) -> str:
    decoded_len = len(base64.b64decode(value))
    if decoded_len > config["crypto"]["max_message_bytes"]:
        raise ValueError("ciphertext exceeds maximum size of %d bytes" % config["crypto"]["max_message_bytes"])
    return value


BoundedCiphertext = Annotated[Base64, AfterValidator(_validate_ciphertext_size)]


class SendMessageRequest(BaseModel):
    recipient_id: int
    ciphertext: BoundedCiphertext
    ratchet_header_enc: Base64

    def ciphertext_bytes(self) -> bytes:
        return base64.b64decode(self.ciphertext)

    def ratchet_header_enc_bytes(self) -> bytes:
        return base64.b64decode(self.ratchet_header_enc)


class MessageResponse(BaseModel):
    id: int
    sender_id: int
    ciphertext: str
    ratchet_header_enc: str


class SendMessageResponse(BaseModel):
    id: int
