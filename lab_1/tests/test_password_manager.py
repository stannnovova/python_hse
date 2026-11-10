"""Тестирование корректности функций и команд по взаимодействию с менеджером паролей."""

import base64
import json
from pathlib import Path

import pytest

from password_logic.password_manager import PasswordManager

MASTER_PASSWORD = "TestMasterPassword123!"


@pytest.fixture  # функция подготавливает данные для тестов
def manager(tmp_path: Path) -> PasswordManager:
    """Создание во времменной папке объекта менеджера паролей с заданным мастер-паролем."""
    storage = tmp_path / "vault.json"
    password_manager = PasswordManager(storage)
    password_manager.init_master(MASTER_PASSWORD)

    return password_manager


def test_master_password(tmp_path: Path) -> None:
    """Тестирование добавления мастер пароля."""
    manager = PasswordManager(tmp_path / "vault.json")

    manager.init_master("TestMasterPassword123!")

    assert manager.unlock("TestMasterPassword123!") is True
    assert manager.unlock("wrong_password") is False


def test_add_entry(manager: PasswordManager) -> None:
    """Проверка появления записи в списке."""
    manager.add_entry("GitHub", "test_user", "TestPassword123!")

    assert "GitHub" in manager.list_entries()


def test_get_entry(manager: PasswordManager) -> None:
    """Проверка правильности возвращения логина и пароля."""
    manager.add_entry("GitHub", "test_user", "TestPassword123!")

    entry = manager.get_entry("GitHub")

    assert entry["login"] == "test_user"
    assert entry["password"] == "TestPassword123!"


def test_delete_entry(manager: PasswordManager) -> None:
    """Проверка исчезновения записи после удаления."""
    manager.add_entry("GitHub", "test_user", "TestPassword123!")

    manager.delete_entry("GitHub")

    assert "GitHub" not in manager.list_entries()


def test_duplicate_entry(manager: PasswordManager) -> None:
    """Проверка отсутствия возможности создать две записи для одного сервиса."""
    manager.add_entry("GitHub", "test_user", "TestPassword123!")

    with pytest.raises(ValueError):
        manager.add_entry("GitHub", "another_user", "AnotherPassword")


def test_persistence(manager: PasswordManager) -> None:
    """Проверка сохранности данных после создания нового менеджера паролей."""
    manager.add_entry("GitHub", "test_user", "TestPassword123!")

    new_manager = PasswordManager(manager.file_path)
    assert new_manager.unlock(MASTER_PASSWORD) is True

    entry = new_manager.get_entry("GitHub")

    assert entry["login"] == "test_user"
    assert entry["password"] == "TestPassword123!"


def test_password_is_encrypted(manager: PasswordManager) -> None:
    """Проверка зашифрованности данных, сохраненных в json."""
    manager.add_entry("GitHub", "test_user", "TestPassword123!")

    content = manager.file_path.read_text(encoding="utf-8")

    assert "TestPassword123!" not in content
    assert "test_user" not in content
    assert MASTER_PASSWORD not in content


def test_wrong_master_password(manager: PasswordManager) -> None:
    """Проверка сценария при неправильно введенном мастер-пароле нет доступа к хранилищу."""
    new_manager = PasswordManager(manager.file_path)

    assert new_manager.unlock("WrongMasterPassword123!") is False

    with pytest.raises(PermissionError):
        new_manager.list_entries()


def test_repeated_initialization(manager: PasswordManager) -> None:
    """Проверка сценария повторной инициализации."""
    original = manager.file_path.read_bytes()

    with pytest.raises(ValueError):
        manager.init_master("AnotherMasterPassword123!")

    assert manager.file_path.read_bytes() == original


def test_short_master_password(tmp_path: Path) -> None:
    """Проверка сценария того, что введенный мастер-пароль короче указанной минимальной длины."""
    manager = PasswordManager(tmp_path / "vault.json")

    with pytest.raises(ValueError):
        manager.init_master("123")

    assert not manager.file_path.exists()


@pytest.mark.parametrize(  # несколько наборов данных для прохождения тестом
    ("name", "login", "password"),
    [
        ("", "test_user", "password123"),
        ("GitHub", "   ", "password123"),
        ("GitHub", "test_user", ""),
    ],
)
def test_empty_entry_fields(
    manage: PasswordManager, name: str, login: str, password: str
) -> None:
    """Проверка того, что при вводе одно из полей будет пустым."""
    with pytest.raises(ValueError):
        manager.add_entry(name, login, password)


def test_missing_entry(manager: PasswordManager) -> None:
    """Проверка сценария того, что будет при попытке получить или удалить несуществующую запись."""
    with pytest.raises(KeyError):
        manager.get_entry("Unknown")

    with pytest.raises(KeyError):
        manager.delete_entry("Unknown")


def test_corrupted_json(tmp_path: Path) -> None:
    """Поврежденный json вызывает ошибку."""
    storage = tmp_path / "vault.json"
    storage.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(ValueError):
        PasswordManager(storage)


def test_modified_ciphertext(manager: PasswordManager) -> None:
    """Обнаружение нарушение целостности шифртекста."""
    manager.add_entry("GitHub", "test_user", "TestPassword123!")

    with manager.file_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    ciphertext = base64.b64decode(data["entries"]["GitHub"]["ciphertext"])

    modified = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    data["entries"]["GitHub"]["ciphertext"] = base64.b64encode(modified).decode("ascii")

    manager.file_path.write_text(json.dumps(data), encoding="utf-8")

    new_manager = PasswordManager(manager.file_path)
    assert new_manager.unlock(MASTER_PASSWORD)

    with pytest.raises(ValueError):
        new_manager.get_entry("GitHub")
