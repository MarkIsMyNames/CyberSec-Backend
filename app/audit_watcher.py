from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TextIO

import inotify_simple

from web3 import Web3

from eth_typing import ChecksumAddress
from app.config import config
from app.logger import logger
from app.vault import read_vault_kv

audit_cfg = config["audit"]


@dataclass
class AuditEvent:
    path: str
    principal: str = ""
    agent: str = ""


def parse_auditd_event(line: str) -> AuditEvent | None:
    key_match = re.search(audit_cfg["auditd_key_pattern"], line)
    if not key_match:
        logger.debug("auditd line has no key field — skipping")
        return None
    key = key_match.group(1)
    if key not in audit_cfg["auditd_key_map"]:
        logger.debug("auditd key %s not watched — skipping", key)
        return None
    path = audit_cfg["auditd_key_map"][key]
    pid_match = re.search(audit_cfg["auditd_pid_pattern"], line)
    uid_match = re.search(audit_cfg["auditd_uid_pattern"], line)
    if not pid_match or not uid_match:
        logger.error("malformed auditd line — missing pid or uid: %s", line.rstrip())
        raise ValueError("malformed auditd line: %s" % line.rstrip())
    return AuditEvent(
        path=path,
        principal=uid_match.group(1),
        agent=pid_match.group(1),
    )


def parse_vault_event(line: str) -> AuditEvent | None:
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None
    if entry.get("type") != "request":
        return None
    request = entry.get("request", {})
    if request.get("path") != audit_cfg["vault_watch_path"]:
        return None
    auth = entry.get("auth", {})
    return AuditEvent(
        path=request["path"],
        principal=auth.get("display_name", ""),
        agent=auth.get("accessor", ""),
    )


def submit_event(event: AuditEvent, w3: Web3, contract, account: ChecksumAddress, private_key: str) -> None:
    logger.info(
        "audit event detected path=%s principal=%s agent=%s — submitting to chain",
        event.path, event.principal, event.agent,
    )
    try:
        event_hash = w3.solidity_keccak(
            abi_types=["string", "string", "string"],
            values=[event.path, event.principal, event.agent],
        )
        nonce = w3.eth.get_transaction_count(account)
        tx = contract.functions.logAccess(event_hash).build_transaction({
            "from": account,
            "nonce": nonce,
            "gas": 100000,
            "gasPrice": w3.eth.gas_price,
        })
        signed = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        logger.info(
            "on-chain event submitted path=%s principal=%s agent=%s event_hash=%s tx=%s",
            event.path, event.principal, event.agent, event_hash.hex(), tx_hash.hex(),
        )
    except Exception as exc:
        logger.error("failed to submit on-chain event path=%s err=%s", event.path, exc)


def run() -> None:
    logger.info("audit watcher starting")
    blockchain_cfg = read_vault_kv(config["vault"]["blockchain_secret_path"])

    with open("app/audit_abi.json") as file:
        abi = json.load(file)

    w3 = Web3(Web3.HTTPProvider(blockchain_cfg["RPC_URL"]))
    if not w3.is_connected():
        logger.error("cannot connect to Sepolia RPC %s", blockchain_cfg["RPC_URL"])
        return
    contract = w3.eth.contract(address=Web3.to_checksum_address(blockchain_cfg["CONTRACT_ADDRESS"]), abi=abi)
    account: ChecksumAddress = Web3.to_checksum_address(w3.eth.account.from_key(blockchain_cfg["WALLET_PRIVATE_KEY"]).address)
    private_key = blockchain_cfg["WALLET_PRIVATE_KEY"]
    logger.info("connected to Sepolia contract=%s account=%s", blockchain_cfg["CONTRACT_ADDRESS"], account)

    sources = [
        (audit_cfg["auditd_log"], parse_auditd_event),
        (audit_cfg["vault_audit_log"], parse_vault_event),
    ]

    handles: list[tuple[TextIO, Callable[[str], AuditEvent | None]]] = []
    inotify = inotify_simple.INotify()
    try:
        handles = [(open(path), parser) for path, parser in sources]
        wd_to_handle: dict[int, tuple[TextIO, Callable[[str], AuditEvent | None]]] = {}
        for file, parser in handles:
            file.seek(0, 2)
            wd = inotify.add_watch(file.name, inotify_simple.flags.MODIFY)
            wd_to_handle[wd] = (file, parser)
            logger.info("tailing %s", file.name)
        logger.info("audit watcher running")
        while True:
            for inotify_event in inotify.read(): # Will block until an update to the file
                file, parser = wd_to_handle[inotify_event.wd]
                while True:
                    line = file.readline()
                    if not line:
                        break
                    event = parser(line)
                    if event:
                        submit_event(event, w3, contract, account, private_key)
    except OSError as exc:
        logger.error("audit watcher failed err=%s", exc)
    finally:
        inotify.close()
        for file, _ in handles:
            file.close()


if __name__ == "__main__":
    run()
