import base64
from http import HTTPStatus

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response

from app.api.deps import get_current_user, require_group_member
from app.auth.rate_limit import GROUP_LIMIT, IP_GROUP_LIMIT, IP_MESSAGES_LIMIT, MESSAGES_LIMIT, ip_limiter, limiter
from app.dependencies import repo_dep
from app.logger import logger
from app.models.group import Group
from app.models.user import User
from app.repositories.group import SQLGroupRepository
from app.schemas.groups import (
    AddMemberRequest,
    CreateGroupRequest,
    CreateGroupResponse,
    GroupListResponse,
    GroupMessageResponse,
    SendGroupMessageResponse,
    GroupResponse,
    RemoveMemberRequest,
    SKDMEntry,
    SKDMResponse,
    SendGroupMessageRequest,
    SendSKDMRequest,
)

router = APIRouter()


@router.get("/", response_model=GroupListResponse)
@limiter.limit(GROUP_LIMIT)
@ip_limiter.limit(IP_GROUP_LIMIT)
async def list_groups(
    request: Request,
    current_user: User = Depends(get_current_user),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> GroupListResponse:
    groups: list[Group] = group_repo.get_groups_for_user(current_user.id)
    members_by_group: dict[int, list[int]] = {g.id: group_repo.get_members(g.id) for g in groups}
    logger.debug("list groups user_id=%d count=%d", current_user.id, len(groups))
    return GroupListResponse(
        groups=[GroupResponse(id=g.id, name=g.name, members=members_by_group[g.id], epoch=g.epoch) for g in groups]
    )


@router.post("/", response_model=CreateGroupResponse, status_code=HTTPStatus.CREATED)
@limiter.limit(GROUP_LIMIT)
@ip_limiter.limit(IP_GROUP_LIMIT)
async def create_group(
    request: Request,
    body: CreateGroupRequest,
    current_user: User = Depends(get_current_user),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> CreateGroupResponse:
    group = group_repo.create_group(body.name, creator_id=current_user.id, initial_members=body.initial_members_bytes() or None)

    logger.info(
        "group created group_id=%d name=%s creator_id=%d initial_members=%d",
        group.id,
        group.name,
        current_user.id,
        len(body.initial_members),
    )

    return CreateGroupResponse(id=group.id)


@router.get("/{group_id}", response_model=GroupResponse)
@limiter.limit(GROUP_LIMIT)
@ip_limiter.limit(IP_GROUP_LIMIT)
async def get_group_info(
    request: Request,
    group_id: int,
    group: Group = Depends(require_group_member),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> GroupResponse:
    members: list[int] = group_repo.get_members(group_id)
    return GroupResponse(id=group_id, name=group.name, members=members, epoch=group.epoch)


@router.post("/{group_id}/members", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(GROUP_LIMIT)
@ip_limiter.limit(IP_GROUP_LIMIT)
async def add_member(
    request: Request,
    body: AddMemberRequest,
    group: Group = Depends(require_group_member),
    current_user: User = Depends(get_current_user),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> Response:
    try:
        group_repo.add_member(group.id, current_user.id, body.user_id, body.skdm_ciphertext_bytes())
    except PermissionError as exc:
        logger.warning(
            "add member failed: not creator group_id=%d requester_id=%d target_id=%d",
            group.id,
            current_user.id,
            body.user_id,
        )
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail=str(exc))
    logger.info("member added group_id=%d user_id=%d", group.id, body.user_id)
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.delete("/{group_id}/members/{user_id}", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(GROUP_LIMIT)
@ip_limiter.limit(IP_GROUP_LIMIT)
async def remove_member(
    request: Request,
    user_id: int,
    body: RemoveMemberRequest = Body(default_factory=RemoveMemberRequest),
    group: Group = Depends(require_group_member),
    current_user: User = Depends(get_current_user),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> Response:
    try:
        group_repo.remove_member(group.id, current_user.id, user_id, body.skdm_ciphertexts_bytes())
    except PermissionError as exc:
        logger.warning(
            "remove member failed: not creator group_id=%d requester_id=%d target_id=%d",
            group.id,
            current_user.id,
            user_id,
        )
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        logger.warning(
            "remove member failed: not a member group_id=%d target_id=%d",
            group.id,
            user_id,
        )
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail=str(exc))
    logger.info("member removed group_id=%d user_id=%d", group.id, user_id)
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.post(
    "/{group_id}/messages",
    response_model=SendGroupMessageResponse,
    status_code=HTTPStatus.CREATED,
)
@limiter.limit(MESSAGES_LIMIT)
@ip_limiter.limit(IP_MESSAGES_LIMIT)
async def send_group_message(
    request: Request,
    body: SendGroupMessageRequest,
    group: Group = Depends(require_group_member),
    current_user: User = Depends(get_current_user),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> SendGroupMessageResponse:
    msg = group_repo.store_group_message(group.id, current_user.id, body.epoch, body.ciphertext_bytes())
    logger.info(
        "group message sent message_id=%d group_id=%d sender_id=%d",
        msg.id,
        group.id,
        current_user.id,
    )
    return SendGroupMessageResponse(id=msg.id)


@router.get("/{group_id}/messages", response_model=list[GroupMessageResponse])
@limiter.limit(MESSAGES_LIMIT)
@ip_limiter.limit(IP_MESSAGES_LIMIT)
async def list_group_messages(
    request: Request,
    group: Group = Depends(require_group_member),
    current_user: User = Depends(get_current_user),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> list[GroupMessageResponse]:
    msgs = group_repo.get_group_messages(group.id, current_user.id)
    return [
        GroupMessageResponse(
            id=m.id,
            group_id=m.group_id,
            epoch=m.epoch,
            ciphertext=base64.b64encode(m.ciphertext).decode(),
        )
        for m in msgs
    ]


@router.delete("/{group_id}/messages/{msg_id}", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(MESSAGES_LIMIT)
@ip_limiter.limit(IP_MESSAGES_LIMIT)
async def revoke_group_message(
    request: Request,
    msg_id: int,
    group: Group = Depends(require_group_member),
    current_user: User = Depends(get_current_user),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> Response:
    if not group_repo.revoke_group_message(msg_id, current_user.id):
        logger.warning(
            "revoke group message failed: not sender message_id=%d group_id=%d user_id=%d",
            msg_id,
            group.id,
            current_user.id,
        )
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail="Cannot revoke this message"
        )
    logger.info("group message revoked message_id=%d group_id=%d user_id=%d", msg_id, group.id, current_user.id)
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.post("/{group_id}/messages/{msg_id}/receipt", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(MESSAGES_LIMIT)
@ip_limiter.limit(IP_MESSAGES_LIMIT)
async def record_group_message_receipt(
    request: Request,
    msg_id: int,
    group: Group = Depends(require_group_member),
    current_user: User = Depends(get_current_user),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> Response:
    group_repo.record_group_receipt(msg_id, current_user.id)
    logger.info("group receipt recorded message_id=%d group_id=%d user_id=%d", msg_id, group.id, current_user.id)
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.post("/{group_id}/skdm", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(MESSAGES_LIMIT)
@ip_limiter.limit(IP_MESSAGES_LIMIT)
async def send_skdms(
    request: Request,
    body: SendSKDMRequest,
    group: Group = Depends(require_group_member),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> Response:
    group_repo.store_skdms(group.id, body.skdm_ciphertexts_bytes())
    logger.info(
        "SKDMs stored group_id=%d count=%d", group.id, len(body.skdm_ciphertexts)
    )
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.get("/{group_id}/skdm", response_model=SKDMResponse)
@limiter.limit(MESSAGES_LIMIT)
@ip_limiter.limit(IP_MESSAGES_LIMIT)
async def pop_skdms(
    request: Request,
    group: Group = Depends(require_group_member),
    current_user: User = Depends(get_current_user),
    group_repo: SQLGroupRepository = Depends(repo_dep(SQLGroupRepository)),
) -> SKDMResponse:
    skdms = group_repo.pop_skdms_for_user(current_user.id, group.id)
    logger.info("popped %d SKDMs group_id=%d user_id=%d", len(skdms), group.id, current_user.id)
    return SKDMResponse(
        skdm_ciphertexts=[SKDMEntry(epoch=ep, ciphertext=base64.b64encode(ct).decode()) for ep, ct in skdms]
    )
