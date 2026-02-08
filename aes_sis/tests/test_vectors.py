from src.aes_core import encrypt_block, decrypt_block
from src.key_schedule import expand_key
from src.utils import hex_to_bytes

def test_aes128_vector():
    key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
    pt  = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a")
    ct  = hex_to_bytes("3ad77bb40d7a3660a89ecaf32466ef97")

    round_keys = expand_key(key)

    out = encrypt_block(pt, round_keys)
    assert out == ct

    back = decrypt_block(out, round_keys)
    assert back == pt

def test_aes192_vector():
    key = hex_to_bytes(
        "8e73b0f7da0e6452c810f32b809079e5"
        "62f8ead2522c6b7b"
    )
    pt = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a")
    ct = hex_to_bytes("bd334f1d6e45f25ff712a214571fa5cc")

    round_keys = expand_key(key)

    out = encrypt_block(pt, round_keys)
    assert out == ct

    back = decrypt_block(out, round_keys)
    assert back == pt

def test_aes256_vector():
    key = hex_to_bytes(
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4"
    )
    pt = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a")
    ct = hex_to_bytes("f3eed1bdb5d2a03c064b5a7e3db181f8")

    round_keys = expand_key(key)

    out = encrypt_block(pt, round_keys)
    assert out == ct

    back = decrypt_block(out, round_keys)
    assert back == pt
