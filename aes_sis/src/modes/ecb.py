from aes_core import encrypt_block, decrypt_block
from key_schedule import expand_key
from padding import pad, unpad

BLOCK_SIZE = 16


def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    round_keys = expand_key(key)
    plaintext = pad(plaintext, BLOCK_SIZE)

    ciphertext = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        ciphertext.extend(encrypt_block(block, round_keys))

    return bytes(ciphertext)


def ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    round_keys = expand_key(key)

    plaintext = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        plaintext.extend(decrypt_block(block, round_keys))

    return unpad(bytes(plaintext), BLOCK_SIZE)
