from pydantic import BaseModel, Field

from app.config import config

VAL_CFG = config["validation"]

Username = Field(
    min_length=VAL_CFG["username_min_length"],
    max_length=VAL_CFG["username_max_length"],
    pattern=VAL_CFG["alnum_re"],
)
Hex = Field(pattern=VAL_CFG["hex_re"])
TotpCode = Field(pattern=VAL_CFG["totp_code_pattern"])


class RegisterRequest(BaseModel):
    username: str = Username
    srp_salt: str = Hex
    srp_verifier: str = Hex


class SRPInitRequest(BaseModel):
    username: str = Username
    client_public: str = Hex


class SRPInitResponse(BaseModel):
    session_id: str
    srp_salt: str
    server_public: str


class SRPVerifyRequest(BaseModel):
    session_id: str
    client_proof: str = Hex


class SRPVerifyResponse(BaseModel):
    server_proof: str
    pre_auth_token: str


class VerifyTOTPRequest(BaseModel):
    totp_code: str = TotpCode
    pre_auth_token: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RegisterResponse(BaseModel):
    user_id: int
    totp_provisioning_uri: str
