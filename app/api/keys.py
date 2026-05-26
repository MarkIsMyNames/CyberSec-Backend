import base64
from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from slowapi.util import get_remote_address

from app.api.deps import get_current_user
from app.auth.rate_limit import ip_keys_limit, keys_limit, limiter
from app.dependencies import repo_dep
from app.models.user import User
from app.logger import logger
from app.repositories.key_bundle import SQLKeyBundleRepository
from app.repositories.user import SQLUserRepository
from app.schemas.keys import (
    KeyBundleResponse,
    KeyBundleUpload,
    OneTimePreKeyCountResponse,
    UploadOneTimePreKeysRequest,
    UserIdentityResponse,
)

router = APIRouter()


@router.post("/bundle", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(keys_limit)
@limiter.limit(ip_keys_limit, key_func=get_remote_address)
async def publish_bundle(
    request: Request,
    body: KeyBundleUpload,
    current_user: User = Depends(get_current_user),
    kb_repo: SQLKeyBundleRepository = Depends(repo_dep(SQLKeyBundleRepository)),
) -> Response:
    kb_repo.store_key_bundle(
        current_user.id,
        body.identity_pub_bytes(),
        body.signed_prekey_pub_bytes(),
        body.signed_prekey_sig_bytes(),
        body.pq_prekey_pub_bytes(),
        body.pq_prekey_sig_bytes(),
    )
    kb_repo.add_one_time_prekeys(current_user.id, body.one_time_prekeys_bytes())
    logger.info(
        "key bundle published user_id=%d opk_count=%d",
        current_user.id,
        len(body.one_time_prekeys),
    )
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.post("/prekeys", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(keys_limit)
@limiter.limit(ip_keys_limit, key_func=get_remote_address)
async def upload_prekeys(
    request: Request,
    body: UploadOneTimePreKeysRequest,
    current_user: User = Depends(get_current_user),
    kb_repo: SQLKeyBundleRepository = Depends(repo_dep(SQLKeyBundleRepository)),
) -> Response:
    kb_repo.add_one_time_prekeys(current_user.id, body.prekeys_bytes())
    logger.info(
        "one-time prekeys uploaded user_id=%d count=%d",
        current_user.id,
        len(body.one_time_prekeys),
    )
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.get("/prekeys/count", response_model=OneTimePreKeyCountResponse)
@limiter.limit(keys_limit)
@limiter.limit(ip_keys_limit, key_func=get_remote_address)
async def get_prekey_count(
    request: Request,
    current_user: User = Depends(get_current_user),
    kb_repo: SQLKeyBundleRepository = Depends(repo_dep(SQLKeyBundleRepository)),
) -> OneTimePreKeyCountResponse:
    count = kb_repo.count_one_time_prekeys(current_user.id)
    logger.debug("prekey count user_id=%d count=%d", current_user.id, count)
    return OneTimePreKeyCountResponse(count=count)


@router.get(
    "/lookup/by-username",
    response_model=UserIdentityResponse,
    dependencies=[Depends(get_current_user)],
)
@limiter.limit(keys_limit)
@limiter.limit(ip_keys_limit, key_func=get_remote_address)
async def lookup_identity_pub_by_username(
    request: Request,
    username: str = Query(),
    kb_repo: SQLKeyBundleRepository = Depends(repo_dep(SQLKeyBundleRepository)),
) -> UserIdentityResponse:
    result = kb_repo.get_identity_pub_by_username(username)
    if result is None:
        logger.warning(
            "identity_pub lookup by username: not found username=%s", username
        )
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="User not found")
    user_id, identity_pub_bytes = result
    logger.debug("identity_pub lookup by username: user_id=%d", user_id)
    return UserIdentityResponse(
        user_id=user_id, identity_pub=base64.b64encode(identity_pub_bytes).decode()
    )


@router.get(
    "/{user_id}",
    response_model=KeyBundleResponse,
    dependencies=[Depends(get_current_user)],
)
@limiter.limit(keys_limit)
@limiter.limit(ip_keys_limit, key_func=get_remote_address)
async def fetch_bundle(
    request: Request,
    user_id: int,
    user_repo: SQLUserRepository = Depends(repo_dep(SQLUserRepository)),
    kb_repo: SQLKeyBundleRepository = Depends(repo_dep(SQLKeyBundleRepository)),
) -> KeyBundleResponse:
    if user_repo.get_user_by_id(user_id) is None:
        logger.warning("fetch bundle failed: user not found user_id=%d", user_id)
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="User not found")
    bundle = kb_repo.get_key_bundle(user_id)
    if bundle is None:
        logger.warning("fetch bundle failed: no bundle user_id=%d", user_id)
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Key bundle not found"
        )
    opk = kb_repo.pop_one_time_prekey(user_id)
    logger.debug("fetch bundle user_id=%d opk_available=%s", user_id, opk is not None)
    return KeyBundleResponse(
        identity_pub=base64.b64encode(bundle.identity_pub).decode(),
        signed_prekey_pub=base64.b64encode(bundle.signed_prekey_pub).decode(),
        signed_prekey_sig=base64.b64encode(bundle.signed_prekey_sig).decode(),
        one_time_prekey=base64.b64encode(opk).decode() if opk else None,
        pq_prekey_pub=base64.b64encode(bundle.pq_prekey_pub).decode(),
        pq_prekey_sig=base64.b64encode(bundle.pq_prekey_sig).decode(),
    )
