from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.auth.rate_limit import AUTH_LIMIT, LOGOUT_LIMIT, REFRESH_LIMIT, limiter
from app.auth.srp_session import srp_init, srp_verify
from app.auth.tokens import (
    InvalidTokenError,
    revoke_token,
    issue_access_token,
    issue_preauth_token,
    issue_refresh_token,
    verify_token,
)
from app.auth.totp import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    get_provisioning_uri,
    verify_totp,
)
from app.dependencies import repo_dep
from app.logger import logger
from app.repositories.user import SQLUserRepository
from app.schemas.auth import (
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    SRPInitRequest,
    SRPInitResponse,
    SRPVerifyRequest,
    SRPVerifyResponse,
    TokenResponse,
    VerifyTOTPRequest,
)


def _client_ip(request: Request) -> str:
    client = request.client
    return client.host if client else "unknown"


router = APIRouter()


@router.post(
    "/register", response_model=RegisterResponse, status_code=HTTPStatus.CREATED
)
@limiter.limit(AUTH_LIMIT)
async def register(
    request: Request,
    body: RegisterRequest,
    repo: SQLUserRepository = Depends(repo_dep(SQLUserRepository)),
) -> RegisterResponse:
    logger.info(
        "register attempt ip=%s username=%s", _client_ip(request), body.username
    )
    if repo.get_user_by_username(body.username) is not None:
        logger.warning("register failed: username taken username=%s", body.username)
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail="Username taken")
    totp_secret = generate_totp_secret()
    totp_enc = encrypt_totp_secret(totp_secret)
    user = repo.create_user(body.username, body.srp_salt, body.srp_verifier, totp_enc)
    uri = get_provisioning_uri(totp_secret, body.username)
    logger.info("register success username=%s user_id=%d", body.username, user.id)
    return RegisterResponse(user_id=user.id, totp_provisioning_uri=uri)


@router.post("/srp-init", response_model=SRPInitResponse)
@limiter.limit(AUTH_LIMIT)
async def srp_init_endpoint(
    request: Request,
    body: SRPInitRequest,
    repo: SQLUserRepository = Depends(repo_dep(SQLUserRepository)),
) -> SRPInitResponse:
    logger.info(
        "srp-init attempt ip=%s username=%s", _client_ip(request), body.username
    )
    user = repo.get_user_by_username(body.username)
    if user is None:
        logger.warning("srp-init failed: unknown username ip=%s", _client_ip(request))
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid credentials"
        )
    try:
        session_id, salt, server_public = srp_init(
            body.username, user.srp_salt, user.srp_verifier, body.client_public
        )
    except Exception:
        logger.warning(
            "srp-init failed: srp error ip=%s username=%s",
            _client_ip(request),
            body.username,
        )
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid credentials"
        )
    logger.info("srp-init success username=%s", body.username)
    return SRPInitResponse(
        session_id=session_id, srp_salt=salt, server_public=server_public
    )


@router.post("/srp-verify", response_model=SRPVerifyResponse)
@limiter.limit(AUTH_LIMIT)
async def srp_verify_endpoint(
    request: Request,
    body: SRPVerifyRequest,
    repo: SQLUserRepository = Depends(repo_dep(SQLUserRepository)),
) -> SRPVerifyResponse:
    logger.info("srp-verify attempt ip=%s", _client_ip(request))
    try:
        username, server_proof = srp_verify(body.session_id, body.client_proof)
    except ValueError:
        logger.warning("srp-verify failed: invalid proof ip=%s", _client_ip(request))
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid credentials"
        )
    logger.info("srp-verify username resolved username=%s ip=%s", username, _client_ip(request))
    user = repo.get_user_by_username(username)
    if user is None:
        logger.warning(
            "srp-verify failed: user vanished username=%s ip=%s",
            username,
            _client_ip(request),
        )
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid credentials"
        )
    token = issue_preauth_token(user.id)
    logger.info("srp-verify success username=%s user_id=%d", username, user.id)
    return SRPVerifyResponse(server_proof=server_proof, pre_auth_token=token)


@router.post("/verify-2fa", response_model=TokenResponse)
@limiter.limit(AUTH_LIMIT)
async def verify_2fa(
    request: Request,
    body: VerifyTOTPRequest,
    repo: SQLUserRepository = Depends(repo_dep(SQLUserRepository)),
) -> TokenResponse:
    logger.info("2fa attempt ip=%s", _client_ip(request))
    try:
        claims = verify_token(body.pre_auth_token, expected_scope="totp_only")
    except InvalidTokenError:
        logger.warning("2fa failed: invalid pre-auth token ip=%s", _client_ip(request))
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid pre-auth token"
        )
    revoke_token(claims)
    user_id = int(claims["sub"])
    user = repo.get_user_by_id(user_id)
    if user is None:
        logger.warning("2fa failed: user not found user_id=%d", user_id)
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="User not found"
        )
    totp_secret = decrypt_totp_secret(user.totp_secret_enc)
    if not verify_totp(totp_secret, body.totp_code):
        logger.warning(
            "2fa failed: wrong totp code user_id=%d ip=%s", user_id, _client_ip(request)
        )
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid TOTP code"
        )
    access = issue_access_token(user_id)
    new_refresh = issue_refresh_token(user_id)
    logger.info("2fa success user_id=%d ip=%s", user_id, _client_ip(request))
    return TokenResponse(access_token=access, refresh_token=new_refresh)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit(REFRESH_LIMIT)
async def refresh_tokens(request: Request, body: RefreshRequest) -> TokenResponse:
    try:
        claims = verify_token(body.refresh_token, expected_scope="refresh")
    except InvalidTokenError:
        logger.warning("token refresh failed: invalid refresh token")
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid refresh token"
        )
    revoke_token(claims)
    user_id = int(claims["sub"])
    access = issue_access_token(user_id)
    new_refresh = issue_refresh_token(user_id)
    logger.info("token refresh success user_id=%d", user_id)
    return TokenResponse(access_token=access, refresh_token=new_refresh)


@router.post("/logout", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(LOGOUT_LIMIT)
async def logout(request: Request, body: RefreshRequest) -> Response:
    try:
        claims = verify_token(body.refresh_token, expected_scope="refresh")
    except InvalidTokenError:
        logger.warning("logout failed: invalid refresh token")
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid refresh token"
        )
    revoke_token(claims)
    logger.info("logout success user_id=%d", int(claims["sub"]))
    return Response(status_code=HTTPStatus.NO_CONTENT)
