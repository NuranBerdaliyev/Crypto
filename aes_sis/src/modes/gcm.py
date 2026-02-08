from aes_core import encrypt_block
from key_schedule import expand_key
from utils import gf128_mul
from rng import random_bytes

BLOCK_SIZE = 16


def xor_blocks(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ghash(aad: bytes, ciphertext: bytes, H: bytes) -> bytes:
    def blocks(data):
        for i in range(0, len(data), 16):
            yield data[i:i + 16].ljust(16, b'\x00')

    Y = b'\x00' * 16

    for block in blocks(aad):
        Y = gf128_mul(xor_blocks(Y, block), H)

    for block in blocks(ciphertext):
        Y = gf128_mul(xor_blocks(Y, block), H)

    lengths = (len(aad) * 8).to_bytes(8, 'big') + (len(ciphertext) * 8).to_bytes(8, 'big')
    Y = gf128_mul(xor_blocks(Y, lengths), H)

    return Y


def gcm_encrypt(plaintext: bytes, key: bytes, aad: bytes = b''):
    round_keys = expand_key(key)

    H = encrypt_block(b'\x00' * 16, round_keys)
    nonce = random_bytes(12)
    counter = 1

    ciphertext = bytearray()

    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        ctr_block = nonce + counter.to_bytes(4, 'big')
        keystream = encrypt_block(ctr_block, round_keys)
        ciphertext.extend(xor_blocks(block, keystream[:len(block)]))
        counter += 1

    tag = ghash(aad, bytes(ciphertext), H)
    S = encrypt_block(nonce + b'\x00\x00\x00\x01', round_keys)
    tag = xor_blocks(tag, S)

    return nonce + bytes(ciphertext) + tag


def gcm_decrypt(data: bytes, key: bytes, aad: bytes = b''):
    round_keys = expand_key(key)

    nonce = data[:12]
    tag = data[-16:]
    ciphertext = data[12:-16]

    H = encrypt_block(b'\x00' * 16, round_keys)
    expected_tag = ghash(aad, ciphertext, H)
    S = encrypt_block(nonce + b'\x00\x00\x00\x01', round_keys)
    expected_tag = xor_blocks(expected_tag, S)

    if expected_tag != tag:
        raise ValueError("GCM authentication failed")

    counter = 1
    plaintext = bytearray()

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        ctr_block = nonce + counter.to_bytes(4, 'big')
        keystream = encrypt_block(ctr_block, round_keys)
        plaintext.extend(xor_blocks(block, keystream[:len(block)]))
        counter += 1

    return bytes(plaintext)
