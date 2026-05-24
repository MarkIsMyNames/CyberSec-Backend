import base64
import binascii
from typing import Annotated

from pydantic import AfterValidator


def _validate_b64(value: str) -> str:
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64: %s" % exc)
    return value


Base64 = Annotated[str, AfterValidator(_validate_b64)]
