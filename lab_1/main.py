import argparse

from interface import run


def main():
    parser = argparse.ArgumentParser(description="консольный менеджер паролей")

    group = parser.add_mutually_exclusive_group()

    group.add_argument("--init", action="store_true", help="создать мастер-пароль")

    group.add_argument("--unlock", action="store_true", help="разблокировать хранилище")

    group.add_argument(
        "--generate", action="store_true", help="сгенерировать надёжный пароль"
    )

    args = parser.parse_args()

    if args.init:
        run("init")
    elif args.unlock:
        run("unlock")
    elif args.generate:
        run("generate")
    else:
        run()


if __name__ == "__main__":
    main()
