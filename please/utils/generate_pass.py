import string
import secrets


def gen_pass(len: int = 20) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation
    generated = "".join(secrets.choice(chars) for _ in range(len))
    return generated