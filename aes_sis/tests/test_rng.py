# tests/test_rng.py

from src.rng import random_bytes, XorShift32


def test_rng_diff():
    """
    RNG не должен быть константным.
    Последовательные вызовы random_bytes должны
    давать разные результаты.
    """
    r1 = random_bytes(32)
    r2 = random_bytes(32)

    assert r1 != r2


def test_prng_seed_reproducible():
    """
    PRNG обязан быть детерминированным
    при фиксированном seed.
    """
    prng1 = XorShift32(seed=123)
    prng2 = XorShift32(seed=123)

    out1 = []
    out2 = []

    for _ in range(4):
        out1.append(prng1.next())
        out2.append(prng2.next())

    assert out1 == out2


def test_prng_progression():
    """
    PRNG должен изменять внутреннее состояние
    между вызовами.
    """
    prng = XorShift32(seed=42)

    a = prng.next()
    b = prng.next()

    assert a != b
