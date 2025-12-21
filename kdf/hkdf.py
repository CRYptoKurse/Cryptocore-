# [file name]: src/kdf/hkdf.py
# [file content begin]
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mac.hmac import HMAC

def derive_key(master_key: bytes, context: str, length: int = 32) -> bytes:
    """
    Получение ключа из мастер-ключа детерминированным HMAC-методом.
    
    Args:
        master_key: мастер-ключ
        context: контекст (строка идентификатора назначения)
        length: желаемая длина ключа в байтах
    
    Returns:
        Производный ключ
    """
    if isinstance(context, str):
        context = context.encode('utf-8')
    
    hmac = HMAC(master_key, 'sha256')
    derived = b''
    counter = 1
    
    # Генерируем достаточно байт
    while len(derived) < length:
        counter_bytes = counter.to_bytes(4, 'big')
        block = hmac.compute_bytes(context + counter_bytes)
        derived += block
        counter += 1
    
    return derived[:length]

# Пример использования
if __name__ == "__main__":
    # Тест детерминированности
    master = b'0' * 32
    key1 = derive_key(master, 'encryption', 32)
    key2 = derive_key(master, 'authentication', 32)
    key1_again = derive_key(master, 'encryption', 32)
    
    assert key1 == key1_again, "Key derivation not deterministic"
    assert key1 != key2, "Different contexts should produce different keys"
    print("Key hierarchy tests passed")
# [file content end]