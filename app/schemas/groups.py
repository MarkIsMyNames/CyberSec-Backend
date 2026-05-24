import base64

from pydantic import BaseModel, Field

from app.config import config
from app.schemas.common import Base64

GroupName = Field(
    min_length=config["validation"]["group_name_min_length"],
    max_length=config["validation"]["group_name_max_length"],
)


class RemoveMemberRequest(BaseModel):
    skdm_ciphertexts: dict[int, Base64] = {}

    def skdm_ciphertexts_bytes(self) -> dict[int, bytes]:
        return {uid: base64.b64decode(ct) for uid, ct in self.skdm_ciphertexts.items()}


class CreateGroupRequest(BaseModel):
    name: str = GroupName
    initial_members: dict[int, Base64] = {}

    def initial_members_bytes(self) -> dict[int, bytes]:
        return {uid: base64.b64decode(ct) for uid, ct in self.initial_members.items()}


class CreateGroupResponse(BaseModel):
    id: int


class AddMemberRequest(BaseModel):
    user_id: int
    skdm_ciphertext: Base64

    def skdm_ciphertext_bytes(self) -> bytes:
        return base64.b64decode(self.skdm_ciphertext)


class SendGroupMessageRequest(BaseModel):
    epoch: int
    ciphertext: Base64

    def ciphertext_bytes(self) -> bytes:
        return base64.b64decode(self.ciphertext)


class SendSKDMRequest(BaseModel):
    skdm_ciphertexts: dict[int, Base64] = Field(min_length=1)

    def skdm_ciphertexts_bytes(self) -> dict[int, bytes]:
        return {uid: base64.b64decode(ct) for uid, ct in self.skdm_ciphertexts.items()}


class SendGroupMessageResponse(BaseModel):
    id: int


class GroupMessageResponse(BaseModel):
    id: int
    group_id: int
    epoch: int
    ciphertext: str


class GroupResponse(BaseModel):
    id: int
    name: str
    members: list[int]
    epoch: int


class SKDMEntry(BaseModel):
    epoch: int
    ciphertext: str


class SKDMResponse(BaseModel):
    skdm_ciphertexts: list[SKDMEntry]


class GroupListResponse(BaseModel):
    groups: list[GroupResponse]
