import secrets
import string
from msvcrt import getwch

from password_manager import PasswordManager


def masked_input(prompt):
    print(prompt, end="", flush=True)
    password = ""

    while True:
        char = getwch()

        if char == "\r":
            print()
            return password

        elif char == "\b":
            if password:
                password = password[:-1]
                print("\b \b", end="", flush=True)

        elif char == "\x03":
            raise KeyboardInterrupt

        elif char in ("\x00", "\xe0"):
            getwch()

        elif char.isprintable():
            password += char
            print("*", end="", flush=True)


def generate_password(length=20):
    groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!@#$%^&*_-",
    ]

    characters = [secrets.choice(group) for group in groups]

    alphabet = "".join(groups)

    characters += [secrets.choice(alphabet) for _ in range(length - len(characters))]

    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


def run(mode=None):
    if mode == "generate":
        print("сгенерированный пароль:", generate_password())
        return

    try:
        manager = PasswordManager()
    except (OSError, ValueError) as error:
        print("Ошибка загрузки:", error)
        return

    if mode == "init":
        password = masked_input("создайте мастер-пароль: ")
        confirm = masked_input("повторите мастер-пароль: ")

        if password != confirm:
            print("пароли не совпадают!")
            return

        try:
            manager.init_master(password)
            print("мастер-пароль создан!")
        except ValueError as error:
            print(error)
        return

    if not manager.is_initialized:
        print("сначала выполните: python main.py --init")
        return

    password = masked_input("мастер-пароль: ")

    if not manager.unlock(password):
        print("неверный мастер-пароль!")
        return

    print("хранилище разблокировано!")

    while True:
        print("\n=== МЕНЕДЖЕР ПАРОЛЕЙ ===")
        print("1. Добавить запись")
        print("2. Посмотреть список")
        print("3. Получить запись")
        print("4. Удалить запись")
        print("0. Выход")

        choice = input("\nвыберите действие: ")

        if choice == "1":
            name = input("название сервиса: ").strip()
            login = input("логин: ").strip()

            if not name or not login:
                print("название и логин обязательны!")
                continue

            pwd = masked_input("пароль: ")
            confirm = masked_input("повторите пароль: ")

            if pwd != confirm:
                print("пароли не совпадают!")
                continue

            try:
                manager.add_entry(name, login, pwd)
                print("запись сохранена!")
            except ValueError as error:
                print(error)

        elif choice == "2":
            entries = manager.list_entries()
            if not entries:
                print("записей пока нет.")
            else:
                for name in entries:
                    print(f"- {name}")

        elif choice == "3":
            name = input("название сервиса: ").strip()

            confirm = masked_input("подтвердите мастер-пароль: ")

            if not manager.verify_master(confirm):
                print("неверный мастер-пароль!")
                continue

            try:
                entry = manager.get_entry(name)
                print(f"логин: {entry['login']}")
                print(f"пароль: {entry['password']}")
            except KeyError:
                print("запись не найдена!")
            except ValueError as error:
                print(error)

        elif choice == "4":
            name = input("название сервиса: ").strip()

            try:
                manager.delete_entry(name)
                print("запись удалена!")
            except KeyError:
                print("запись не найдена!")

        elif choice == "0":
            print("до свидания!")
            break

        else:
            print("неизвестная команда!")
