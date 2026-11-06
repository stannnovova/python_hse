import base64
import binascii
import hashlib
import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ITERATIONS = 600_000


def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def derive_keys(password: str, salt: bytes,
                iterations: int = ITERATIONS) -> tuple[bytes, bytes]:
    result = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=64
    )
    return result[:32], result[32:]


def encrypt_entry(key: bytes, name: str,
                  login: str, password: str) -> dict:
    data = json.dumps(
        {"login": login, "password": password},
        ensure_ascii=False
    ).encode("utf-8")

    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(key).encrypt(
        nonce, data, name.encode("utf-8")
    )

    return {
        "nonce": encode(nonce),
        "ciphertext": encode(encrypted)
    }


def decrypt_entry(key: bytes, name: str, record: dict) -> dict:
    try:
        nonce = decode(record["nonce"])
        encrypted = decode(record["ciphertext"])

        data = AESGCM(key).decrypt(
            nonce, encrypted, name.encode("utf-8")
        )

        result = json.loads(data)

        if not isinstance(result, dict) or not all(
            isinstance(result.get(field), str)
            for field in ("login", "password")
        ):
            raise ValueError("неверный формат записи")

        return result

    except (
        InvalidTag,
        ValueError,
        TypeError,
        KeyError,
        binascii.Error,
        UnicodeDecodeError
    ) as error:
        raise ValueError(
            "запись повреждена или была изменена"
        ) from error
