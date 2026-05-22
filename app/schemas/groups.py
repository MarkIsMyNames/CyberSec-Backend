import base64

from pydantic import BaseModel, Field

from app.config import config
from app.schemas.common import Base64

GroupName = Field(min_length=config["validation"]["group_name_min_length"], max_length=config["validation"]["group_name_max_length"])


class CreateGroupRequest(BaseModel):
    name: str = GroupName
    initial_members: list[int] = []


class CreateGroupResponse(BaseModel):
    id: int
    name: str


class AddMemberRequest(BaseModel):
    user_id: int


class SendGroupMessageRequest(BaseModel):
    ciphertext: Base64
    skdm_ciphertexts: dict[int, Base64] | None = None

    def ciphertext_bytes(self) -> bytes:
        return base64.b64decode(self.ciphertext)


class GroupMessageResponse(BaseModel):
    id: int
    group_id: int
    ciphertext: str
    sent_at: int


class GroupResponse(BaseModel):
    id: int
    name: str
    members: list[int]


class SKDMResponse(BaseModel):
    skdm_ciphertexts: list[str]


class GroupListResponse(BaseModel):
    groups: list[GroupResponse]
