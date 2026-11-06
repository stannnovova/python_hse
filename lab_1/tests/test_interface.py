import sys

import interface
from password_manager import PasswordManager

import main


def test_repeated_interface_init(tmp_path, monkeypatch):
    storage = tmp_path / "vault.json"
    original_password = "OriginalMaster123!"
    new_password = "AnotherMaster123!"

    passwords = iter(
        [
            original_password,
            original_password,
            new_password,
            new_password,
        ]
    )

    monkeypatch.setattr(
        interface,
        "PasswordManager",
        lambda: PasswordManager(storage),
    )

    monkeypatch.setattr(
        interface,
        "masked_input",
        lambda prompt: next(passwords),
    )

    monkeypatch.setattr(sys, "argv", ["main.py", "--init"])

    main.main()
    original_data = storage.read_bytes()

    main.main()

    assert storage.read_bytes() == original_data

    assert PasswordManager(storage).unlock(original_password) is True
    assert PasswordManager(storage).unlock(new_password) is False
