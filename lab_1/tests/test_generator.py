import string

import pytest
from interface import generate_password


@pytest.mark.parametrize("length", [4, 12, 20, 32])
def test_password_length(length):
    password = generate_password(length)

    assert len(password) == length


def test_password_contains_all_character_types():
    password = generate_password(20)

    assert any(char in string.ascii_lowercase for char in password)
    assert any(char in string.ascii_uppercase for char in password)
    assert any(char in string.digits for char in password)
    assert any(char in "!@#$%^&*_" for char in password)


@pytest.mark.parametrize("length", [0, 3])
def test_invalid_password_length(length):
    with pytest.raises(ValueError):
        generate_password(length)
