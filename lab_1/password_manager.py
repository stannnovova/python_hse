
import hmac
import json
import os
import secrets
from pathlib import Path

from crypto_logic import (
    ITERATIONS,
    decode,
    decrypt_entry,
    derive_keys,
    encode,
    encrypt_entry,
)


class PasswordManager:
    def __init__(self, file_path=None):
        self.file_path = (
            Path(file_path) if file_path is not None
            else Path(__file__).resolve().parent / "data" / "vault.json"
        )
        self._data = self._load()
        self.entries = self._data["entries"] if self._data is not None else {}
        self._key = None

    @property
    def is_initialized(self):
        return self._data is not None

    def _load(self):
        if not self.file_path.exists():
            return None

        try:
            with self.file_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except json.JSONDecodeError as error:
            raise ValueError("JSON хранилища повреждён") from error

        if (
            not isinstance(data, dict)
            or data.get("version") != 1
            or not isinstance(data.get("master"), dict)
            or not isinstance(data.get("entries"), dict)
        ):
            raise ValueError("неподдерживаемый формат vault.json")

        return data

    def _persist(self):
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.file_path.with_name(self.file_path.name + ".tmp")

        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(self._data, file, ensure_ascii=False, indent=4)

        os.replace(temp_path, self.file_path)

    def init_master(self, password):
        if self.is_initialized:
            raise ValueError("хранилище уже инициализировано")

        if len(password) < 12:
            raise ValueError(
                "мастер-пароль должен содержать минимум 12 символов"
            )

        salt = secrets.token_bytes(16)
        verifier, key = derive_keys(password, salt)

        self._data = {
            "version": 1,
            "master": {
                "salt": encode(salt),
                "hash": encode(verifier),
                "iterations": ITERATIONS
            },
            "entries": {}
        }

        self.entries = self._data["entries"]
        self._key = key
        self._persist()

    def verify_master(self, password):
        if not self.is_initialized:
            return False

        master = self._data["master"]
        verifier, _ = derive_keys(
            password,
            decode(master["salt"]),
            master["iterations"]
        )

        return hmac.compare_digest(verifier, decode(master["hash"]))

    def unlock(self, password) -> bool:
        if not self.is_initialized:
            return False

        master = self._data["master"]
        verifier, key = derive_keys(
            password,
            decode(master["salt"]),
            master["iterations"]
        )

        if not hmac.compare_digest(verifier, decode(master["hash"])):
            self._key = None
            return False

        self._key = key
        return True

    def _require_key(self):
        if self._key is None:
            raise PermissionError("сначала разблокируйте хранилище")
        return self._key

    def add_entry(self, name, login, password):
        key = self._require_key()

        if not name.strip() or not login.strip() or not password:
            raise ValueError("все поля обязательны")

        if name in self.entries:
            raise ValueError("запись уже существует")

        self.entries[name] = encrypt_entry(key, name, login, password)
        self._persist()

    def list_entries(self):
        self._require_key()
        return list(self.entries.keys())

    def get_entry(self, name):
        key = self._require_key()
        return decrypt_entry(key, name, self.entries[name])

    def delete_entry(self, name):
        self._require_key()
        del self.entries[name]
        self._persist()
