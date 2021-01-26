#!/usr/bin/python3

from Crypto import Random
from Crypto.Cipher import AES


def pad(string):
    if isinstance(string, str):
        string = string.encode("utf-8")
    return string + b"\0" * (AES.block_size - len(string) % AES.block_size)


def encrypt(message, key):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)


def decrypt(ciphertext, key):
    iv = ciphertext[: AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size :])
    return plaintext.rstrip(b"\0")


def encrypt_file(file_name, key):
    with open(file_name, "rb") as file:
        plaintext = file.read()

    enc = encrypt(plaintext, key)

    with open(file_name + ".enc", "wb") as file:
        file.write(enc)


def decrypt_file(file_name, key):
    with open(file_name, "rb") as file:
        ciphertext = file.read()

    dec = decrypt(ciphertext, key)

    with open(file_name[:-4] + ".dec", "wb") as file:
        file.write(dec)


KEY = (
    b"\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI"
    b"{\xa2$\x05(\xd5\x18"
)
