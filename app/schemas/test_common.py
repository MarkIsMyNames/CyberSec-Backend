import base64

import pytest
from pydantic import BaseModel, ValidationError

from app.schemas.common import Base64


class Model(BaseModel):
    value: Base64


def test_accepts_valid_base64():
    m = Model(value=base64.b64encode(b"hello").decode())
    assert m.value == base64.b64encode(b"hello").decode()


def test_rejects_invalid_base64():
    with pytest.raises(ValidationError):
        Model(value="not!!base64")


def test_rejects_bad_padding():
    # base64.b64encode(b"hello") == "aGVsbG8=" — stripped padding is invalid
    with pytest.raises(ValidationError):
        Model(value="aGVsbG8")


def test_accepts_empty_string():
    m = Model(value="")
    assert m.value == ""


def test_accepts_base64_with_padding():
    m = Model(value=base64.b64encode(b"x" * 10).decode())
    assert base64.b64decode(m.value) == b"x" * 10
