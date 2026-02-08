from aes_core import encrypt_block
from key_schedule import expand_key
from rng import random_bytes

BLOCK_SIZE = 16


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ctr_encrypt(data: bytes, key: bytes) -> bytes:
    round_keys = expand_key(key)

    nonce = random_bytes(8)
    counter = 0
    out = bytearray(nonce)

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]

        counter_block = nonce + counter.to_bytes(8, 'big')
        keystream = encrypt_block(counter_block, round_keys)

        out.extend(xor_bytes(block, keystream[:len(block)]))
        counter += 1

    return bytes(out)


def ctr_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    round_keys = expand_key(key)

    nonce = ciphertext[:8]
    data = ciphertext[8:]

    counter = 0
    out = bytearray()

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]

        counter_block = nonce + counter.to_bytes(8, 'big')
        keystream = encrypt_block(counter_block, round_keys)

        out.extend(xor_bytes(block, keystream[:len(block)]))
        counter += 1

    return bytes(out)
