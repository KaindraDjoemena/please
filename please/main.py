import os

from please.app import App


def make_instance() -> App:
    app = App(
        db_name="please/passwords.db",
        pass_table="pass_table",
        mp_table="mp_table"
    )
    return app


def main():
    if not os.path.exists("please/passwords.db"):
        app = make_instance()
        app.user_signup()
        return

    app = make_instance()
    if app.user_signin():
        app.menu()


if __name__ == "__main__":
    main()