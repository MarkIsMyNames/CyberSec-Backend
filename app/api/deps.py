from http import HTTPStatus

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.tokens import InvalidTokenError, TokenClaims, revoke_token, verify_token
from app.dependencies import repo_dep
from app.logger import logger
from app.models.group import Group
from app.models.user import User
from app.repositories.group import SQLGroupRepository
from app.repositories.user import SQLUserRepository
from app.schemas.auth import RefreshRequest, VerifyTOTPRequest

# Extracts the token from the Authorization: Bearer <token> header.
bearer = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    repo: SQLUserRepository = Depends(repo_dep(SQLUserRepository)),
) -> User:
    try:
        claims = verify_token(credentials.credentials, expected_scope="full")
    except InvalidTokenError:
        logger.warning("auth failed: invalid token")
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid token")
    user = repo.get_user_by_id(int(claims["sub"]))
    if user is None:
        logger.warning("auth failed: user not found user_id=%s", claims["sub"])
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="User not found"
        )
    logger.debug("auth success user_id=%d", user.id)
    return user


def require_valid_refresh(body: RefreshRequest) -> TokenClaims:
    try:
        claims = verify_token(body.refresh_token, expected_scope="refresh")
    except InvalidTokenError:
        logger.warning("refresh token invalid")
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid refresh token")
    revoke_token(claims)
    return claims


def require_preauth_user(
    body: VerifyTOTPRequest,
    repo: SQLUserRepository = Depends(repo_dep(SQLUserRepository)),
) -> User:
    try:
        claims = verify_token(body.pre_auth_token, expected_scope="totp_only")
    except InvalidTokenError:
        logger.warning("pre-auth token invalid")
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid pre-auth token")
    revoke_token(claims)
    user = repo.get_user_by_id(int(claims["sub"]))
    if user is None:
        logger.warning("pre-auth user not found user_id=%s", claims["sub"])
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="User not found")
    return user


def require_group_member(
    group_id: int,
    current_user: User = Depends(get_current_user),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> Group:
    group = group_repo.get_group(group_id)
    if group is None:
        logger.warning("group access failed: not found group_id=%d user_id=%d", group_id, current_user.id)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Group not found")
    if not group_repo.is_member(group_id, current_user.id):
        logger.warning("group access failed: not a member group_id=%d user_id=%d", group_id, current_user.id)
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Not a member")
    return group
