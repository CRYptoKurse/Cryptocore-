# CryptoCore

Криптографическая библиотека и инструмент командной строки.

## Возможности

- Шифрование AES (ECB, CBC, CFB, OFB, CTR, GCM, ETM)
- Хеширование (SHA-256, SHA3-256)
- HMAC аутентификация
- Выработка ключей (PBKDF2)
- Криптографический ГСЧ

## Установка

```bash
pip install pycryptodome
git clone https://github.com/CRYptoKurse/Cryptocore-.git
cd cryptocore
Использование
bash
# Шифрование
python cryptocore.py encrypt -a aes -m gcm -i файл.txt -o файл.enc

# Дешифрование
python cryptocore.py encrypt --decrypt -a aes -m gcm -i файл.enc -o файл.txt

# Хеширование
python cryptocore.py dgst -a sha256 -i файл.txt

# Выработка ключа
python cryptocore.py derive --password "пароль" --iterations 100000
Документация
API документация

Руководство пользователя

Руководство разработчика

Тестирование
bash
python tests/run_tests.py
Безопасность
См. SECURITY.md для сообщения об уязвимостях.

Лицензия
MIT License

text

Эти файлы содержат все необходимые документы для Sprint 8:

1. **API.md** - полная документация API
2. **USERGUIDE.md** - руководство пользователя с примерами
3. **CHANGELOG.md** - история изменений
4. **CONTRIBUTING.md** - руководство для участников
5. **SECURITY.md** - политика безопасности
6. **run_tests.py** - скрипт для запуска тестов
7. **README.md** - базовое описание проекта

Все документы на русском языке и готовы к размещению в соответствующей структуре каталогов.
