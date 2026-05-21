from __future__ import annotations

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from http import HTTPStatus

from app.auth.tokens import InvalidTokenError, verify_token
from app.dependencies import repo_dep
from app.models.user import User
from app.repositories.user import SQLUserRepository

# Extracts the token from the Authorization: Bearer <token> header.
bearer = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    repo: SQLUserRepository = Depends(repo_dep(SQLUserRepository)),
) -> User:
    try:
        claims = verify_token(credentials.credentials, expected_scope="full")
    except InvalidTokenError:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid token")
    user = repo.get_user_by_id(int(claims["sub"]))
    if user is None:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, detail="User not found"
        )
    return user
