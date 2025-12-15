 КРАТКИЙ ОТЧЕТ: СПРИНТ 4 ВЫПОЛНЕН
 КАК ИСПОЛЬЗОВАТЬ:

# Хеширование файлов
cryptocore dgst --algorithm sha256 --input file.txt
cryptocore dgst --algorithm sha3-256 --input data.bin --output hash.txt

# Шифрование (старое)
cryptocore encrypt --algorithm aes --mode cbc --input secret.txt
cryptocore encrypt --decrypt --algorithm aes --mode cbc --input secret.enc --key <ключ>
 КАК РАБОТАЕТ:
SHA-256: Реализован с нуля (Merkle-Damgård, блоки 512 бит)

SHA3-256: Использует hashlib (Keccak, губчатая конструкция)

Обработка: Файлы читаются частями (8KB), память не зависит от размера

Вывод: Формат хеш_значение имя_файла как в *sum утилитах

ВЫПОЛНЕННЫЕ ТРЕБОВАНИЯ:

CLI: Новая команда dgst, отдельная от шифрования

Алгоритмы: SHA-256 (с нуля) + SHA3-256

Большие файлы: Потоковая обработка частями

Тесты: NIST векторы, пустой файл, лавинный эффект, ошибки

Совместимость: Формат вывода как у стандартных утилит

 ВСЕ ОБЯЗАТЕЛЬНЫЕ ТРЕБОВАНИЯ СПРИНТА 4 ВЫПОЛНЕНЫ
