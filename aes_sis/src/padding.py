BLOCK_SIZE = 16  # размер блока AES в байтах

# --- Добавление PKCS#7 ---
def pad(data: bytes) -> bytes:
    """
    Добавляет PKCS#7 padding к данным.
    Если длина данных кратна BLOCK_SIZE, добавляется полный блок padding.
    """
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    if pad_len == 0:
        pad_len = BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

# --- Удаление PKCS#7 ---
def unpad(data: bytes) -> bytes:
    """
    Убирает PKCS#7 padding.
    Выбрасывает ValueError, если паддинг некорректен.
    """
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Данные некорректной длины для PKCS#7")
    
    pad_len = data[-1]
    
    if pad_len == 0 or pad_len > BLOCK_SIZE:
        raise ValueError("Неверный padding")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Неверный padding")
    
    return data[:-pad_len]
