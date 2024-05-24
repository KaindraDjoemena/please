import os
from functools import cache
import argon2
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Argon2Hasher:
    @staticmethod
    def hash_password(password: str) -> str:
        return argon2.PasswordHasher().hash(password)
    
    @staticmethod
    def verify_password(hash: str | bytes, password: str | bytes) -> bool:
        return argon2.PasswordHasher().verify(hash, password)


class AESCipher:
    @cache
    def derive_key(self, key, salt, key_len=32) -> bytes:
        '''KEY DERIVATION FUNCTION'''

        # IMPORTANT
        # memory cost default is 2**16 (64 MB)
        # memory cost used is 2**15 (32 MB) for faster operations, but reduced security
        hasher = argon2.PasswordHasher(type=argon2.low_level.Type.ID, memory_cost=2**15, hash_len=65)
        hash = hasher.hash(key.encode("utf-8"), salt=salt)

        hashed_key = hash.split("$")[-1]    # get argon2 output hash
        return bytes(hashed_key[:key_len].encode("utf-8"))


    def encrypt(self, key, data):
        '''ENCRYPTION FUNCTION'''

        salt = os.urandom(16)               # safely generate salt
        d_key = self.derive_key(key, salt)  # derive encryption key

        iv = os.urandom(16)
        self.cipher = AES.new(d_key, AES.MODE_CBC, iv)
        padded = pad(data.encode("utf-8"), 16)
        encrypted = self.cipher.encrypt(padded)

        return salt, b64encode(iv + encrypted)  # return the salt, concatinate iv and encryption

    @cache
    def decrypt(self, key, data, salt):
        '''DECRYPTION FUNCTION'''

        d_key = self.derive_key(key, salt)

        raw = b64decode(data)
        self.cipher = AES.new(d_key, AES.MODE_CBC, raw[:16])    # parse iv (16 bytes) from the encrypted data
        decrypted = self.cipher.decrypt(raw[16:])
        unpadded = unpad(decrypted, 16)
        return unpadded