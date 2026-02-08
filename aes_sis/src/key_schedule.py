from aes_core import S_BOX as SBOX

# --- Rcon для раундов ---
RCON = [
    0x00,
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,
    0x6C,0xD8,0xAB,0x4D,0x9A,0x2F,0x5E,0xBC,0x63,0xC6,
    0x97,0x35,0x6A,0xD4,0xB3,0x7D,0xFA,0xEF,0xC5,0x91
]

# --- Вспомогательные функции ---
def sub_word(word):
    """Применить S-box к каждому байту слова (4 байта)"""
    return [SBOX[b] for b in word]

def rot_word(word):
    """Циклический сдвиг слова (4 байта)"""
    return word[1:] + word[:1]

# --- Расширение ключа ---
def expand_key(key_bytes):
    """
    Возвращает список раундовых ключей в виде матриц 4x4 байта
    Поддержка ключей 128 / 192 / 256 бит
    """
    key_len = len(key_bytes)
    assert key_len in (16, 24, 32), "Ключ должен быть 128/192/256 бит"

    # Определяем количество раундов
    if key_len == 16:
        Nk, Nr = 4, 10
    elif key_len == 24:
        Nk, Nr = 6, 12
    else:
        Nk, Nr = 8, 14

    # Разбиваем исходный ключ на слова по 4 байта
    words = [list(key_bytes[i:i+4]) for i in range(0, key_len, 4)]
    i = Nk

    while len(words) < 4*(Nr+1):
        temp = words[-1].copy()
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i//Nk]
        elif Nk > 6 and i % Nk == 4:  # для AES-256
            temp = sub_word(temp)
        # XOR с предыдущим словом Nk позиций назад
        temp = [t ^ w for t, w in zip(temp, words[-Nk])]
        words.append(temp)
        i += 1

    # Формируем раундовые ключи 4x4
    round_keys = []
    for r in range(Nr+1):
        key_matrix = []
        for c in range(4):
            # Сбор слова для столбца
            key_matrix.append(words[r*4 + c])
        # транспонируем для работы с state в aes_core (row-major)
        round_keys.append([list(row) for row in zip(*key_matrix)])
    return round_keys
