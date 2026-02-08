def bytes_to_hex(b: bytes) -> str:
    return ''.join(f'{x:02x}' for x in b)

def hex_to_bytes(h: str) -> bytes:
    # убираем пробелы, если есть
    h = h.replace(' ', '')
    return bytes.fromhex(h)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def gf_add(a: int, b: int) -> int:
    return a ^ b
def gf_mult(a: int, b: int) -> int:
    p = 0
    while b:
        if b & 1:
            p ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:  # если вышли за 8 бит
            a ^= 0x11b
    return p & 0xff
def gf_inv(a: int) -> int:
    if a == 0:
        return 0
    # a^(2^8-2) = a^254
    result = 1
    for _ in range(254):
        result = gf_mult(result, a)
    return result
def gf128_mul(x: bytes, y: bytes) -> bytes:
    R = 0xe1000000000000000000000000000000

    x = int.from_bytes(x, 'big')
    y = int.from_bytes(y, 'big')

    z = 0
    v = x

    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1

    return z.to_bytes(16, 'big')