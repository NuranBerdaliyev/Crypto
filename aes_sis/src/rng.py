import os
import time

# --- Сбор энтропии ---
def collect_entropy() -> int:
    """
    Возвращает 32-битное целое число, собранное из нескольких источников:
    - текущее время в микросекундах
    - случайные байты из os.urandom
    """
    t = int(time.time() * 1_000_000) & 0xFFFFFFFF  # время в микросекундах
    r = int.from_bytes(os.urandom(4), 'little')    # 4 случайных байта
    return t ^ r

# --- Xorshift32 PRNG ---
class XorShift32:
    def __init__(self, seed=None):
        self.state = seed or collect_entropy()
        if self.state == 0:
            self.state = 1  # состояние не может быть нулевым

    def next(self) -> int:
        x = self.state
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        self.state = x & 0xFFFFFFFF
        return self.state

# --- Инициализация PRNG ---
_prng = XorShift32()

# --- Генерация случайных байт ---
def random_bytes(n: int) -> bytes:
    """
    Возвращает n случайных байт, используя xorshift32 PRNG
    """
    out = bytearray()
    while len(out) < n:
        r = _prng.next()
        out.extend(r.to_bytes(4, 'little'))
    return bytes(out[:n])

