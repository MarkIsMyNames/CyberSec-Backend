import base64
from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from app.api.deps import get_current_user
from app.config import config
from app.auth.rate_limit import IP_MESSAGES_LIMIT, MESSAGES_LIMIT, ip_limiter, limiter
from app.dependencies import repo_dep
from app.logger import logger
from app.models.user import User
from app.repositories.message import SQLMessageRepository
from app.schemas.messages import MessageResponse, SendMessageRequest


router = APIRouter()


@router.post("/", response_model=MessageResponse, status_code=HTTPStatus.CREATED)
@limiter.limit(MESSAGES_LIMIT)
@ip_limiter.limit(IP_MESSAGES_LIMIT)
async def send_message(
    request: Request,
    body: SendMessageRequest,
    current_user: User = Depends(get_current_user),
    msg_repo: SQLMessageRepository = Depends(repo_dep(SQLMessageRepository)),
) -> MessageResponse:
    try:
        msg = msg_repo.store_message(
            sender_id=current_user.id,
            recipient_id=body.recipient_id,
            ciphertext=body.ciphertext_bytes(),
            ratchet_header_enc=body.ratchet_header_enc_bytes(),
        )
    except OverflowError:
        logger.warning("send message failed: inbox full recipient_id=%d", body.recipient_id)
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS, detail="Recipient inbox is full"
        )
    logger.info("message sent message_id=%d sender_id=%d recipient_id=%d", msg.id, current_user.id, body.recipient_id)
    return MessageResponse(
        id=msg.id,
        ciphertext=base64.b64encode(msg.ciphertext).decode(),
        ratchet_header_enc=base64.b64encode(msg.ratchet_header_enc).decode(),
        sent_at=int(msg.sent_at),
    )


@router.get("/", response_model=list[MessageResponse])
@limiter.limit(MESSAGES_LIMIT)
@ip_limiter.limit(IP_MESSAGES_LIMIT)
async def list_messages(
    request: Request,
    current_user: User = Depends(get_current_user),
    msg_repo: SQLMessageRepository = Depends(repo_dep(SQLMessageRepository)),
    limit: int = Query(default=config["messaging"]["page_default"], ge=1, le=config["messaging"]["page_max"]),
    offset: int = Query(default=0, ge=0),
) -> list[MessageResponse]:
    msgs = msg_repo.get_messages_for_user(current_user.id, limit=limit, offset=offset)
    return [
        MessageResponse(
            id=message.id,
            ciphertext=base64.b64encode(message.ciphertext).decode(),
            ratchet_header_enc=base64.b64encode(message.ratchet_header_enc).decode(),
            sent_at=int(message.sent_at),
        )
        for message in msgs
    ]


@router.post("/{message_id}/receipt", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(MESSAGES_LIMIT)
@ip_limiter.limit(IP_MESSAGES_LIMIT)
async def mark_receipt(
    request: Request,
    message_id: int,
    current_user: User = Depends(get_current_user),
    msg_repo: SQLMessageRepository = Depends(repo_dep(SQLMessageRepository)),
) -> Response:
    if not msg_repo.record_receipt(message_id, current_user.id):
        logger.warning(
            "receipt failed: message not found message_id=%d user_id=%d",
            message_id,
            current_user.id,
        )
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Message not found"
        )
    logger.debug("receipt recorded message_id=%d user_id=%d", message_id, current_user.id)
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.delete("/{message_id}", status_code=HTTPStatus.NO_CONTENT)
@limiter.limit(MESSAGES_LIMIT)
@ip_limiter.limit(IP_MESSAGES_LIMIT)
async def revoke(
    request: Request,
    message_id: int,
    current_user: User = Depends(get_current_user),
    msg_repo: SQLMessageRepository = Depends(repo_dep(SQLMessageRepository)),
) -> Response:
    if not msg_repo.revoke_message(message_id, current_user.id):
        logger.warning("revoke failed: not sender or not found message_id=%d user_id=%d", message_id, current_user.id)
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail="Cannot revoke this message"
        )
    logger.info("message revoked message_id=%d user_id=%d", message_id, current_user.id)
    return Response(status_code=HTTPStatus.NO_CONTENT)
