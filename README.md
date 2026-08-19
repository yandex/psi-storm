# PSI Storm - Private Set Intersection (Пересечение приватных множеств)

Private Set Intersection с использованием Диффи-Хеллмана на эллиптических кривых (ECDH).

Основано на: https://ieeexplore.ieee.org/document/6234849

## Требования

- OpenSSL 3.0+
- g++

```bash
# Ubuntu/Debian
sudo apt install libssl-dev g++ make

# macOS (требуется Homebrew)
brew install openssl@3 make
```

## Сборка

```bash
make
```

## Использование

Обе стороны (Алиса и Боб) выполняют одни и те же команды независимо друг от друга.

### 1. Инициализация

```bash
./psi init
```

Создаёт файл `secret-config.ini` с приватным ключом. Храните его в секрете.

### 2. Шаг 1 - Хеширование и шифрование своих данных

```bash
./psi step1
```

Вход: `input-step1.txt` (одно значение на строку)  
Выход: `send-this-to-partner-step1.txt` → отправить партнёру

Пример файла `input-step1.txt`:
```
79123456789
79999999999
71111111111
```

### 3. Шаг 2 - Шифрование данных партнёра

Переименуйте полученный от партнера файл в `input-step2.txt`, затем:

```bash
./psi step2
```

Вход: `input-step2.txt` (выход шага 1 партнёра)  
Выход: `send-this-to-partner-step2.txt` → отправить партнёру

### 4. Сравнение

Переименуйте полученный от партнера файл в `received-step2.txt`, затем:

```bash
./psi compare
```

Вход:
- `received-step2.txt` (выход шага 2 партнёра)
- `send-this-to-partner-step2.txt` (свой выход шага 2, остаётся с прошлого шага)
- `input-step1.txt` (исходные значения, нужны для восстановления пересечения; не требуется в режиме shuffle)

Выход: `intersection-result.txt` - это финальный результат

Вместо переименования можно обновить конфиг `secret-config.ini`, указав путь к полученному файлу (параметр `partner_step2_output`).

## Конфигурация

Отредактируйте `secret-config.ini` для изменения путей к файлам или включения режима shuffle (поиск только количества общих значений без раскрытия этих общий значений).

## Docker

```bash
docker build -t psi-storm .
docker run -v $(pwd):/data psi-storm init --config /data/secret-config.ini
docker run -v $(pwd):/data psi-storm step1 --config /data/secret-config.ini
```

## Тестирование

```bash
make test
```

---

## Протокол

A - Алиса, B - Боб

$S_A$ - секретные значения Алисы, $S_B$ - секретные значения Боба

a - приватный ключ Алисы, b - приватный ключ Боба

$[1] A \rightarrow B: S_A^a$

$[2] B \rightarrow A: S_B^b$

$[3] A \rightarrow B: S_B^{ba}$

$[4] B \rightarrow A: S_A^{ab}$

## Пример

Наборы данных:
```
Алиса: 1 3 8 13
Боб:   3 13 20 1337 6
```

Пересечение: 3 и 13

**Выход шага 1 (Алиса):** сжатые точки EC (66 hex-символов каждая)
```
023EC020EECBC74118F3413AA3402E91DD7EE5B4F14B7E416112965FE1D2807B52
0353B044678EEDA8E05A58F1D719AD7E623C75816D61D6ECBEAABD664C2C736B40
026493C1B9832D9CC363BF9BAB690107C0F22C7188A87DEDBFBBFBADB5E3472C3A
036C205599DA32375E0F5FB4FF4DA7F999C565E8219F83C3A4720653A773419052
```

**Выход шага 1 (Боб):** сжатые точки EC
```
0205BA023BE0B5A43F27B5BBE4A9B57F6C6667EDE72B44022BA08B185533EE99D8
030600923B8EB418BEB5D5183D33CDC0D149B3EAD4B572EA72E2E467A681340717
02F43DDC165C7A0FC14E0ACD239E5D60637E75AFED144368DF4245BE9F4831A9CF
03F7B50FB679A9A047FA43E1318B22104DD9CC4E837E058B905472E04CB73A021B
027EBA1EB4BD4602438E10B33FABD324258ECE5CDC2B251537BED6C114D7590290
```

**Шаг 2: Алиса шифрует данные Боба:** SHA256-хеши (64 hex-символа каждый)
```
4EA95B1AB2D3269C3C2D407EB38DA246F5D6ED6EAAAEF32B130FF85AD1D2CC95
CDB47BEA5B983FFA4096B9DD2DD61F426E4A8A3EB72699C8C78AE11D818ECB7E
00D99D7AEFBC5EEA649946752359D0715DABA3BBBF11B2DFB79BF275BA1D7609
C9E32D7FB7657927FB04D63B4DED172079EDBF3C831325A62D60D510DF8771A8
E3194500790C09E5DB8D3AB2210635B9E74A1424493EFCD15BE1296E9FC0F7E2
```

**Шаг 2: Боб шифрует данные Алисы:** SHA256-хеши
```
539CB730A6FE081A5B50AE3C4DD3098CCA952A7E7FB30739204359E596F2BAF9
4EA95B1AB2D3269C3C2D407EB38DA246F5D6ED6EAAAEF32B130FF85AD1D2CC95
36969C0125EC1661BC81D3D5FF7368E06781A192E08831B75665E7CD77957980
CDB47BEA5B983FFA4096B9DD2DD61F426E4A8A3EB72699C8C78AE11D818ECB7E
```

**Сравнение:** Общие хеши:
```
4EA95B1AB2D3269C3C2D407EB38DA246F5D6ED6EAAAEF32B130FF85AD1D2CC95
CDB47BEA5B983FFA4096B9DD2DD61F426E4A8A3EB72699C8C78AE11D818ECB7E
```

Алиса находит их на позициях 2 и 4 в зашифрованных данных Боба → соответствуют позициям 2 и 4 в её входных данных → значения **3** и **13**.
