"""Модуль описывает криптографические операции менеджера паролей.

Алгоритм: на вход подается мастер-пароль, к нему добавляется соль из 16 случайных байтов,
после чего алгоритмом SHA-256 получается ключ и verifyer для проверки пароля.

При добавлении записи, логин и пароль превращаются в json а затем в байты utf-8. Генерируется nonce - 12 байтов,
он позволяет шифровать одинаковые данные одним ключом с разными результатами. Один nonce используется
единожды.

При расшифровке используется тот же секретный ключ, что и для шифровки, режим работы AES - GCM дополнительно проверяет целостность данных. При повторном вводе мастер-пароля программа читает из json исходную соль и число итераций,
алгоритм повторно вычисляет ключ и verifyer, и если последний совпадает с сохраненным, то проверка считается успешной.
"""

import base64
import binascii
import hashlib
import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 700500


def encode(data: bytes) -> str:
    """Преобразование бинарных данных в строку, которую можно сохранять в json."""
    return base64.b64encode(data).decode("ascii")


def decode(text: str) -> bytes:
    """Восстановление исходных байтов из строки Base64."""
    return base64.b64decode(text, validate=True)


def derive_keys(
    password: str, salt: bytes, iterations: int = ITERATIONS
) -> tuple[bytes, bytes]:
    """На основе мастер-пароля и соли возвращает 32-байтовые значения verifyer и ключ."""
    result = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=64
    )
    return result[:32], result[32:]


def encrypt_entry(key: bytes, name: str, login: str, password: str) -> dict[str, str]:
    """Принимает логин и пароль, зашифровывает их с AES-GCM и возвращает данные для сохранеения в json."""
    data = json.dumps(
        {"login": login, "password": password}, ensure_ascii=False
    ).encode("utf-8")

    nonce = secrets.token_bytes(12)  # 12 - стандарт для AES-GCM
    encrypted = AESGCM(key).encrypt(nonce, data, name.encode("utf-8"))

    return {"nonce": encode(nonce), "ciphertext": encode(encrypted)}


def decrypt_entry(key: bytes, name: str, record: dict[str, str]) -> dict[str, str]:
    """Восстанавливает логин и пароль из зашифрованной записи, проверяет ее подлинность и правильность структуры."""
    try:
        nonce = decode(record["nonce"])
        encrypted = decode(record["ciphertext"])

        data = AESGCM(key).decrypt(nonce, encrypted, name.encode("utf-8"))

        result = json.loads(data)

        if not isinstance(result, dict) or not all(
            isinstance(result.get(field), str) for field in ("login", "password")
        ):
            raise ValueError("неверный формат записи")

        return result

    except (
        InvalidTag,
        ValueError,
        TypeError,
        KeyError,
        binascii.Error,
        UnicodeDecodeError,
    ) as error:
        raise ValueError("запись повреждена или была изменена") from error
