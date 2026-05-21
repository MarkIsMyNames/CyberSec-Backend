import base64
from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.api.deps import get_current_user
from app.auth.rate_limit import KEYS_LIMIT, limiter
from app.dependencies import repo_dep
from app.models.user import User
from app.repositories.key_bundle import SQLKeyBundleRepository
from app.repositories.user import SQLUserRepository
from app.schemas.keys import KeyBundleResponse, KeyBundleUpload, OneTimePreKeyCountResponse, UploadOneTimePreKeysRequest

router = APIRouter()


@router.post("/bundle", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(KEYS_LIMIT)
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
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.post("/prekeys", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(KEYS_LIMIT)
async def upload_prekeys(
    request: Request,
    body: UploadOneTimePreKeysRequest,
    current_user: User = Depends(get_current_user),
    kb_repo: SQLKeyBundleRepository = Depends(repo_dep(SQLKeyBundleRepository)),
) -> Response:
    kb_repo.add_one_time_prekeys(current_user.id, body.prekeys_bytes())
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.get("/prekeys/count", response_model=OneTimePreKeyCountResponse)
@limiter.limit(KEYS_LIMIT)
async def get_prekey_count(
    request: Request,
    current_user: User = Depends(get_current_user),
    kb_repo: SQLKeyBundleRepository = Depends(repo_dep(SQLKeyBundleRepository)),
) -> OneTimePreKeyCountResponse:
    count = kb_repo.count_one_time_prekeys(current_user.id)
    return OneTimePreKeyCountResponse(count=count)


@router.get("/{user_id}", response_model=KeyBundleResponse, dependencies=[Depends(get_current_user)])
@limiter.limit(KEYS_LIMIT)
async def fetch_bundle(
    request: Request,
    user_id: int,
    user_repo: SQLUserRepository = Depends(repo_dep(SQLUserRepository)),
    kb_repo: SQLKeyBundleRepository = Depends(repo_dep(SQLKeyBundleRepository)),
) -> KeyBundleResponse:
    if user_repo.get_user_by_id(user_id) is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="User not found")
    bundle = kb_repo.get_key_bundle(user_id)
    if bundle is None:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Key bundle not found"
        )
    opk = kb_repo.pop_one_time_prekey(user_id)
    return KeyBundleResponse(
        user_id=user_id,
        identity_pub=base64.b64encode(bundle.identity_pub).decode(),
        signed_prekey_pub=base64.b64encode(bundle.signed_prekey_pub).decode(),
        signed_prekey_sig=base64.b64encode(bundle.signed_prekey_sig).decode(),
        one_time_prekey=base64.b64encode(opk).decode() if opk else None,
        pq_prekey_pub=base64.b64encode(bundle.pq_prekey_pub).decode(),
        pq_prekey_sig=base64.b64encode(bundle.pq_prekey_sig).decode(),
    )
