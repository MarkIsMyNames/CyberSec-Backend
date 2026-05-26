import os

import hvac

from app.config import config
from app.logger import logger

vault_cfg = config["vault"]


def read_vault_kv(path: str) -> dict[str, str]:
    try:
        addr = os.environ["VAULT_ADDR"]
        role_id = os.environ["VAULT_ROLE_ID"]
        secret_id = os.environ["VAULT_SECRET_ID"]
    except KeyError as exc:
        raise RuntimeError("Vault bootstrap failed: missing env var %s" % exc) from exc
    try:
        client = hvac.Client(url=addr)
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        result = client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=vault_cfg["mount_point"],
        )
        data: dict[str, str] = result["data"]["data"]
        return data
    except Exception as exc:
        raise RuntimeError("Vault secret fetch failed: %s" % exc) from exc


def load_secrets() -> None:
    data = read_vault_kv(vault_cfg["app_secret_path"])
    try:
        os.environ["SERVER_MASTER_SECRET"] = data["SERVER_MASTER_SECRET"]
        os.environ["JWT_SECRET_KEY"] = data["JWT_SECRET_KEY"]
        os.environ["DATABASE_URL"] = data["DATABASE_URL"]
    except KeyError as exc:
        raise RuntimeError("Vault secret missing expected key: %s" % exc) from exc
    logger.info("secrets loaded from Vault")
