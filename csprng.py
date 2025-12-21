import os
import sys


def generate_random_bytes(num_bytes: int) -> bytes:
    """
    Генерирует криптографически стойкую случайную байтовую строку.

    Аргументы:
        num_bytes: количество байт для генерации

    Возвращает:
        Байтовую строку длиной num_bytes

    Исключения:
        Вызывает RuntimeError, если генерация не удалась
    """
    try:
        return os.urandom(num_bytes)
    except Exception as e:
        raise RuntimeError(f"Ошибка генерации случайных чисел: {e}")