"""Модуль отвечает за тестирование сгенерированного пароля."""

import string

import pytest

from password_logic.interface import generate_password


@pytest.mark.parametrize("length", [4, 12, 20, 32])
def test_password_length(length: int) -> None:
    """Проверка пароля на соответствие с заданной длиной."""
    password = generate_password(length)

    assert len(password) == length


def test_password_contains_all_character_types() -> None:
    """Проверка необходимых свойств сгенерированного пароля."""
    password = generate_password(15)

    assert any(char in string.ascii_lowercase for char in password)
    assert any(char in string.ascii_uppercase for char in password)
    assert any(char in string.digits for char in password)
    assert any(char in "!@#$%^&*_" for char in password)


@pytest.mark.parametrize("length", [0, 3])
def test_invalid_password_length(length: int) -> None:
    """Тест на пароль с длиной, короче минимальной."""
    with pytest.raises(ValueError):
        generate_password(length)
