from aes_core import encrypt_block, decrypt_block
from key_schedule import expand_key
from padding import pad, unpad
from rng import random_bytes

BLOCK_SIZE = 16


def xor_blocks(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def cbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    round_keys = expand_key(key)
    plaintext = pad(plaintext, BLOCK_SIZE)

    iv = random_bytes(BLOCK_SIZE)
    prev = iv
    ciphertext = bytearray(iv)

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        xored = xor_blocks(block, prev)
        enc = encrypt_block(xored, round_keys)
        ciphertext.extend(enc)
        prev = enc

    return bytes(ciphertext)


def cbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    round_keys = expand_key(key)

    iv = ciphertext[:BLOCK_SIZE]
    data = ciphertext[BLOCK_SIZE:]

    prev = iv
    plaintext = bytearray()

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        dec = decrypt_block(block, round_keys)
        plaintext.extend(xor_blocks(dec, prev))
        prev = block

    return unpad(bytes(plaintext), BLOCK_SIZE)
