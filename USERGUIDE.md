## Файл 2: `docs/USERGUIDE.md`

```markdown
# Руководство пользователя CryptoCore

## Содержание
1. [Установка](#установка)
2. [Быстрый старт](#быстрый-старт)
3. [Шифрование файлов](#шифрование-файлов)
4. [Хеширование](#хеширование)
5. [HMAC](#hmac)
6. [Выработка ключей](#выработка-ключей)
7. [Устранение проблем](#устранение-проблем)
8. [Рекомендации по безопасности](#рекомендации-по-безопасности)

## Установка

### Требования
- Python 3.7 или выше
- pip

### Установка зависимостей
```bash
pip install pycryptodome
Проверка установки
bash
python cryptocore.py --help
Быстрый старт
Зашифровать файл
bash
python cryptocore.py encrypt --algorithm aes --mode gcm --input file.txt --output file.enc
Расшифровать файл
bash
python cryptocore.py encrypt --decrypt --algorithm aes --mode gcm --input file.enc --output file.txt
Вычислить хеш
bash
python cryptocore.py dgst --algorithm sha256 --input file.txt
Шифрование файлов
Поддерживаемые режимы
ECB, CBC, CFB, OFB, CTR

GCM (рекомендуется)

ETM (Encrypt-then-MAC)

Примеры
Базовое шифрование CBC:

bash
python cryptocore.py encrypt \
  --algorithm aes \
  --mode cbc \
  --key 00112233445566778899aabbccddeeff \
  --input data.txt \
  --output data.enc
GCM с ассоциированными данными:

bash
python cryptocore.py encrypt \
  --algorithm aes \
  --mode gcm \
  --key 00112233445566778899aabbccddeeff \
  --input database.sql \
  --output database.enc \
  --aad "версия=3.2"
Хеширование
SHA-256
bash
python cryptocore.py dgst \
  --algorithm sha256 \
  --input file.iso
SHA3-256
bash
python cryptocore.py dgst \
  --algorithm sha3-256 \
  --input file.txt
Сохранение в файл
bash
python cryptocore.py dgst \
  --algorithm sha256 \
  --input документ.pdf \
  --output документ.pdf.sha256
HMAC
Генерация HMAC
bash
python cryptocore.py dgst \
  --algorithm sha256 \
  --hmac \
  --key $(python -c "import os; print(os.urandom(32).hex())") \
  --input сообщение.txt
Проверка HMAC
bash
python cryptocore.py dgst \
  --algorithm sha256 \
  --hmac \
  --key <ключ> \
  --input файл.txt \
  --verify expected.hmac
Выработка ключей
PBKDF2
bash
python cryptocore.py derive \
  --password "мой_пароль" \
  --iterations 100000 \
  --length 32
Из файла
bash
python cryptocore.py derive \
  --password-file пароль.txt \
  --iterations 100000
Из переменной окружения
bash
export MY_PASSWORD="пароль"
python cryptocore.py derive \
  --env-var MY_PASSWORD \
  --iterations 100000
Устранение проблем
Ошибки аутентификации (GCM/ETM)
Проверьте правильность ключа

Убедитесь, что AAD совпадает

Проверьте целостность данных

Неверная длина ключа
AES: 16, 24 или 32 байта

ETM: минимум 32 байта

Файл слишком короткий
GCM: минимум 28 байт

Другие режимы: минимум размер блока

Включение подробного вывода
bash
python cryptocore.py encrypt -v -a aes -m gcm -i in.txt -o out.enc
Рекомендации по безопасности
Управление ключами
Генерируйте ключи достаточной длины

Храните ключи в безопасном месте

Регулярно меняйте ключи

Используйте ключевые контейнеры

Пароли
Минимум 16 символов

Используйте менеджеры паролей

Не используйте пароли повторно

Используйте пассфразы

Режимы шифрования
Избегайте ECB

Используйте GCM для новых систем

ETM если GCM недоступен

Всегда проверяйте аутентификацию

Операционные практики
Проверяйте целостность после передачи

Используйте AAD для контекста

Очищайте конфиденциальные данные

Обновляйте библиотеки

Быстрая справка
Шифрование
bash
python cryptocore.py encrypt -a aes -m gcm -i вход -o выход
Дешифрование
bash
python cryptocore.py encrypt --decrypt -a aes -m gcm -i зашифровано -o расшифровано
Хеширование
bash
python cryptocore.py dgst -a sha256 -i файл
HMAC
bash
python cryptocore.py dgst -a sha256 --hmac --key <ключ> -i файл
Выработка ключей
bash
python cryptocore.py derive --password "пароль" --iterations 100000
Сравнение с другими инструментами
OpenSSL
bash
# CryptoCore
python cryptocore.py encrypt -a aes -m cbc -i файл -o зашифровано

# OpenSSL
openssl enc -aes-256-cbc -in файл -out зашифровано
GPG
bash
# CryptoCore (симметричное)
python cryptocore.py encrypt -a aes -m gcm -i файл -o зашифровано

# GPG
gpg --symmetric --cipher-algo AES256 файл
sha256sum
bash
# CryptoCore
python cryptocore.py dgst -a sha256 -i файл

# sha256sum
sha256sum файл
