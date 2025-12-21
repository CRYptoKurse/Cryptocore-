import hashlib


class SHA3_256:
    def __init__(self):
        self._hash = hashlib.sha3_256()

    def update(self, data):
        """Обновление хеша новыми данными"""
        self._hash.update(data)

    def digest(self):
        """Возвращает финальный хеш в виде байтов"""
        return self._hash.digest()

    def hexdigest(self):
        """Возвращает хеш в виде шестнадцатеричной строки"""
        return self._hash.hexdigest()