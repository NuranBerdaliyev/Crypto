from src.modes.ecb import ecb_encrypt, ecb_decrypt
from src.modes.cbc import cbc_encrypt, cbc_decrypt
from src.modes.ctr import ctr_encrypt, ctr_decrypt
from src.modes.gcm import gcm_encrypt, gcm_decrypt

import pytest

def test_ecb_roundtrip():
    data = b"HELLO WORLD"
    key = b"\x00" * 16

    ct = ecb_encrypt(data, key)
    pt = ecb_decrypt(ct, key)

    assert pt == data

def test_ecb_multiblock():
    data = b"A" * 100
    key = b"\x01" * 16

    ct = ecb_encrypt(data, key)
    pt = ecb_decrypt(ct, key)

    assert pt == data

def test_cbc_roundtrip():
    data = b"HELLO CBC MODE"
    key = b"\x02" * 16

    ct = cbc_encrypt(data, key)
    pt = cbc_decrypt(ct, key)

    assert pt == data

def test_cbc_iv_random():
    key = b"\x03" * 16

    ct1 = cbc_encrypt(b"test", key)
    ct2 = cbc_encrypt(b"test", key)

    # первые 16 байт — IV
    assert ct1[:16] != ct2[:16]

def test_ctr_stream():
    data = b"CTR MODE DOES NOT USE PADDING"
    key = b"\x04" * 16

    ct = ctr_encrypt(data, key)
    pt = ctr_decrypt(ct, key)

    assert pt == data

def test_ctr_no_padding():
    data = b"A" * 37
    key = b"\x05" * 16

    ct = ctr_encrypt(data, key)

    # 12 байт nonce + plaintext
    assert len(ct) == 12 + len(data)

def test_gcm_roundtrip():
    data = b"AUTHENTICATED DATA"
    key = b"\x06" * 16
    aad = b"header"

    ct, tag = gcm_encrypt(data, key, aad)
    pt = gcm_decrypt(ct, tag, key, aad)

    assert pt == data

def test_gcm_auth_fail():
    data = b"DO NOT TAMPER"
    key = b"\x07" * 16
    aad = b"aad"

    ct, tag = gcm_encrypt(data, key, aad)

    # портим ciphertext
    tampered = ct[:-1] + bytes([ct[-1] ^ 1])

    with pytest.raises(Exception):
        gcm_decrypt(tampered, tag, key, aad)

