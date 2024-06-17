from base64 import (
    b64encode,
    b64decode
)
from random import randint


def ascii_to_base64(
    asciiStr: "str"
) -> "str":
    asciiStr = asciiStr.encode()
    asciiStr = b64encode(asciiStr)
    asciiStr = asciiStr.decode()

    return asciiStr


def base64_to_ascii(
    b64Str: "str"
) -> "str":
    b64Str = b64Str.encode()
    b64Str = b64decode(b64Str)
    b64Str = b64Str.decode()

    return b64Str


def char_xor(
    char1: "str", 
    char2: "str"
) -> "str":
    xor = ord(char1) ^ ord(char2)
    xor = chr(xor)

    return xor


def otp(
    message: "str", 
    key: "str"
) -> "str":
    message = [
        char_xor(mchar, kchar) 
        for mchar, kchar in zip(message, key)
    ]
    message = "".join(message)

    return message


def otp_encrypt_b64(
    message: "str",
    key: "str"
) -> "str":
    key = base64_to_ascii(key)
    message = otp(message, key)
    message = ascii_to_base64(message)

    return message


def otp_decrypt_b64(
    message: "str",
    key: "str"
):
    key = base64_to_ascii(key)
    message = base64_to_ascii(message)
    message = otp(message, key)

    return message


def generate_key_b64(
    length: "int"
) -> "str":
    key = ""
    for __ in range(length):
        key += chr(randint(0, 255))
    key = ascii_to_base64(key)

    return key


if __name__ == "__main__":

    message = input("Type a text: ")
    key = generate_key_b64(len(message))

    encrypted = otp_encrypt_b64(message, key)
    decrypted = otp_decrypt_b64(encrypted, key)

    print("Original text:", message)
    print("Generated key:", key)
    print("Encrypted text:", encrypted)
    print("Decrypted text:", decrypted)
    print(
        "Test status:", 
        "OK" if message == decrypted else "FAIL")
