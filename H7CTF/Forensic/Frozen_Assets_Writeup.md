# H7CTF'26 — Frozen Assets

- **Category:** Static Forensics
- **Difficulty:** Insane
- **Points:** 565
- **Challenge:** Frozen Assets
- **Flag:** `H7CTF{750b6f18160c332f9f2b}`

---

## 1. Challenge description

> DESKTOP-M-HALE keeps the finance team's books, and overnight every file on its E: drive turned to expensive noise. Security pulled a full image of the box while it was still warm.
>
> Whatever froze the assets left a copy of itself behind. Rude of it, and useful to you.

Ta được cung cấp file:

```text
IR-DESKTOP-M-HALE.zip
```

Mục tiêu là khôi phục các file trên ổ `E:` đã bị ransomware mã hóa và tìm flag.

Điểm quan trọng trong mô tả là:

> **Whatever froze the assets left a copy of itself behind.**

Tức là mẫu ransomware vẫn còn nằm đâu đó trong image/triage export. Nếu khôi phục được binary này và reverse thuật toán mã hóa, ta có thể giải mã toàn bộ dữ liệu.

---

# 2. Triage ban đầu

Giải nén image:

```bash
mkdir case
unzip IR-DESKTOP-M-HALE.zip -d case
cd case
```

Liệt kê file:

```bash
find . -type f -printf '%p\n'
```

Ta thấy cấu trúc chính:

```text
./ProgramData/Avast Software/Avast/chest/index.xml
./ProgramData/Avast Software/Avast/chest/$AV_ASW/$VAULT/vault.db
./Program Files/Avast Software/Avast/aswntsqlite.dll

./E/Q3_financials.xlsx.enc
./E/board_minutes.docx.enc
./E/id_scan_cfo.png.enc
./E/wallet.dat.enc
./E/master_password.kdbx.enc
./E/recovery_codes.txt.enc
./E/server_key.pem.enc

./READ_ME.txt
```

Nội dung `READ_ME.txt`:

```bash
cat READ_ME.txt
```

Kết quả:

```text
Triage export from DESKTOP-M-HALE (finance workstation).
User reports files on E: are encrypted. Avast quarantined something before it ran.
Recover the E: files.
```

Như vậy hướng điều tra rất rõ:

1. Các file trên `E:` có đuôi `.enc`.
2. Avast đã quarantine một file trước đó.
3. Cần tìm ransomware trong Avast quarantine.
4. Reverse ransomware để lấy thuật toán/key.
5. Giải mã các file `.enc`.

---

# 3. Tìm mẫu ransomware trong Avast quarantine

Mở metadata của Avast:

```bash
cat 'ProgramData/Avast Software/Avast/chest/index.xml'
```

Kết quả:

```xml
<?xml version="1.0"?>
<Chest>
  <ChestEntry>
    <ChestId>1</ChestId>
    <OrigFolder>C:\Users\m.hale\Downloads</OrigFolder>
    <OrigFileName>setup_helper.tmp</OrigFileName>
    <Virus>Win32:Evo-gen</Virus>
    <TransferTime>1758300000</TransferTime>
    <IDPBlob>4944500a01</IDPBlob>
  </ChestEntry>

  <ChestEntry>
    <ChestId>2</ChestId>
    <OrigFolder>C:\Users\m.hale\Downloads</OrigFolder>
    <OrigFileName>ProtonVPN_x64final.exe</OrigFileName>
    <Virus>Win32:RansomX-gen [Ransom]</Virus>
    <TransferTime>1758470000</TransferTime>
    <IDPBlob>4944500a02</IDPBlob>
  </ChestEntry>
</Chest>
```

Entry đáng chú ý:

```text
ChestId      : 2
OrigFileName : ProtonVPN_x64final.exe
Virus        : Win32:RansomX-gen [Ransom]
```

Đây gần như chắc chắn là ransomware cần tìm.

Tuy nhiên binary không tồn tại trực tiếp trong thư mục chest. Avast lưu dữ liệu trong:

```text
ProgramData/Avast Software/Avast/chest/$AV_ASW/$VAULT/vault.db
```

Nếu thử mở trực tiếp bằng SQLite sẽ thất bại vì file không bắt đầu bằng magic:

```text
SQLite format 3
```

Như vậy `vault.db` đã bị Avast obfuscate/mã hóa.

---

# 4. Phân tích `aswntsqlite.dll`

Trong image có file:

```text
Program Files/Avast Software/Avast/aswntsqlite.dll
```

Tên DLL gợi ý đây là thành phần liên quan tới SQLite của Avast.

Kiểm tra export table:

```bash
objdump -x 'Program Files/Avast Software/Avast/aswntsqlite.dll' \
  | grep -A25 -i 'Export Table'
```

Ta thấy:

```text
Export Address Table -- Ordinal Base 1

[0] 00004060  aswNtSqliteVaultKey
[1] 00001450  sqlite3_open
```

Export quan trọng nhất là:

```text
aswNtSqliteVaultKey
```

Tên này gần như nói thẳng rằng đây là key dùng cho Avast SQLite vault.

---

## 4.1 `aswNtSqliteVaultKey` không phải function

Dùng `nm`:

```bash
nm -n 'Program Files/Avast Software/Avast/aswntsqlite.dll' \
  | grep -A5 -B5 aswNtSqliteVaultKey
```

Kết quả quan trọng:

```text
00000002b5d34000 r .rdata
00000002b5d34060 R aswNtSqliteVaultKey
00000002b5d38060 R __dyn_tls_init_callback
```

Ký hiệu `R` cho biết symbol nằm trong vùng **read-only data**, không phải code.

Vì symbol kế tiếp bắt đầu tại:

```text
0x2b5d38060
```

còn key bắt đầu tại:

```text
0x2b5d34060
```

nên độ dài key là:

```text
0x2b5d38060 - 0x2b5d34060 = 0x4000
```

Tức:

```text
key length = 0x4000 = 16384 bytes
```

---

# 5. Chuyển RVA của key thành file offset

Từ export table:

```text
aswNtSqliteVaultKey RVA = 0x4060
```

Xem section table:

```bash
objdump -h 'Program Files/Avast Software/Avast/aswntsqlite.dll'
```

Phần cần chú ý:

```text
Idx Name    Size      VMA               File off
2   .rdata  00004618  00000002b5d34000  00001e00
```

`.rdata` bắt đầu tại RVA:

```text
0x4000
```

Key bắt đầu ở:

```text
RVA 0x4060
```

Do đó key nằm cách đầu `.rdata`:

```text
0x4060 - 0x4000 = 0x60
```

File offset:

```text
0x1e00 + 0x60 = 0x1e60
```

Vậy:

```text
aswNtSqliteVaultKey
file offset = 0x1e60
length      = 0x4000
```

---

# 6. Giải mã `vault.db`

Ta XOR `vault.db` với mảng key 0x4000 byte và lặp key theo chu kỳ.

Tạo `decrypt_vault.py`:

```python
from pathlib import Path

dll_path = Path(
    "Program Files/Avast Software/Avast/aswntsqlite.dll"
)

vault_path = Path(
    "ProgramData/Avast Software/Avast/chest/$AV_ASW/$VAULT/vault.db"
)

dll = dll_path.read_bytes()
vault = vault_path.read_bytes()

KEY_OFFSET = 0x1e60
KEY_SIZE = 0x4000

key = dll[KEY_OFFSET:KEY_OFFSET + KEY_SIZE]

plain = bytes(
    b ^ key[i % len(key)]
    for i, b in enumerate(vault)
)

Path("vault_decrypted.db").write_bytes(plain)

print(plain[:16])
```

Chạy:

```bash
python3 decrypt_vault.py
```

Kết quả:

```text
b'SQLite format 3\x00'
```

Đây chính xác là SQLite magic:

```text
53 51 4c 69 74 65 20 66
6f 72 6d 61 74 20 33 00

SQLite format 3\x00
```

Như vậy ta đã giải đúng Avast vault.

---

# 7. Đọc SQLite database

Nếu máy có `sqlite3`:

```bash
sqlite3 vault_decrypted.db '.tables'
```

Database có 3 bảng:

```text
vault
crossRef
stream
```

Schema:

```sql
CREATE TABLE vault (
    id INTEGER PRIMARY KEY,
    filename TEXT,
    virus TEXT,
    size INTEGER,
    added INTEGER
);

CREATE TABLE crossRef (
    vaultid INTEGER,
    streamId INTEGER
);

CREATE TABLE stream (
    streamId INTEGER PRIMARY KEY,
    data BLOB
);
```

Query metadata:

```bash
sqlite3 -header -column vault_decrypted.db \
'SELECT * FROM vault;'
```

Kết quả quan trọng:

```text
id  filename                                         virus                        size
--  -----------------------------------------------  ---------------------------  ------
1   C:\Users\m.hale\Downloads\setup_helper.tmp       Win32:Evo-gen                34210
2   C:\Users\m.hale\Downloads\ProtonVPN_x64final.exe Win32:RansomX-gen [Ransom]  153282
```

Xem mapping:

```bash
sqlite3 -header -column vault_decrypted.db \
'SELECT * FROM crossRef;'
```

Kết quả:

```text
vaultid  streamId
-------  --------
1        1
2        2
```

Như vậy:

```text
ProtonVPN_x64final.exe -> streamId 2
```

### Nếu không có `sqlite3` CLI

```python
import sqlite3

con = sqlite3.connect("vault_decrypted.db")

for row in con.execute("SELECT * FROM vault"):
    print(row)

for row in con.execute("SELECT * FROM crossRef"):
    print(row)
```

---

# 8. Khôi phục ransomware

Trích `streamId = 2`:

```python
import sqlite3
from pathlib import Path

con = sqlite3.connect("vault_decrypted.db")

blob = con.execute(
    "SELECT data FROM stream WHERE streamId = 2"
).fetchone()[0]

Path("ProtonVPN_x64final.exe").write_bytes(blob)
print("size =", len(blob))
```

Kết quả:

```text
size = 153282
```

Kiểm tra:

```bash
file ProtonVPN_x64final.exe
```

```text
PE32+ executable for MS Windows 5.02 (console), x86-64
```

Hash SHA-256:

```bash
sha256sum ProtonVPN_x64final.exe
```

```text
4f8f3dc93e50bd3a78b6a478a70c5b80f8746abaeab4c550ca88fd6c11d2b9d1
```

---

# 9. Static analysis ransomware

Kiểm tra imports:

```bash
objdump -p ProtonVPN_x64final.exe \
  | grep -E \
'CryptAcquireContext|CryptCreateHash|CryptHashData|CryptDeriveKey|CryptSetKeyParam|CryptEncrypt|CreateFile|ReadFile|WriteFile|DeleteFile'
```

Ta thấy:

```text
CryptAcquireContextA
CryptCreateHash
CryptHashData
CryptDeriveKey
CryptSetKeyParam
CryptEncrypt

CreateFileA
ReadFile
WriteFile
DeleteFileA
```

Đây là Windows CryptoAPI.

Tìm string:

```bash
strings -a ProtonVPN_x64final.exe | grep -E '\.enc|AES|Cryptographic'
```

Ta thấy:

```text
%s.enc
Microsoft Enhanced RSA and AES Cryptographic Provider
```

Điều này khớp với các file bị mã hóa có đuôi `.enc`.

---

# 10. Binary còn symbol — tìm `main`

```bash
objdump -t ProtonVPN_x64final.exe | grep -E ' main$|encrypt_file'
```

Ta thấy:

```text
encrypt_file.isra.0
main
```

Disassemble `main`:

```bash
objdump -d -Mintel \
  --disassemble=main \
  ProtonVPN_x64final.exe
```

---

# 11. Reverse key generation

Đoạn đáng chú ý trong `main`:

```asm
mov    edx,0x8003
...
call   [CryptCreateHash]
```

Prototype:

```c
BOOL CryptCreateHash(
    HCRYPTPROV hProv,
    ALG_ID     Algid,
    HCRYPTKEY  hKey,
    DWORD      dwFlags,
    HCRYPTHASH *phHash
);
```

Trên Windows x64:

```text
RCX = arg1
RDX = arg2
R8  = arg3
R9  = arg4
arg5 nằm trên stack
```

Ở đây:

```text
Algid = 0x8003
```

Constant:

```text
0x8003 = CALG_MD5
```

Ransomware đang tạo MD5 hash object.

---

## 11.1 Lỗi quan trọng: `CryptHashData()` hash 0 byte

Ngay sau đó:

```asm
mov    rcx,QWORD PTR [rsp+0x40]
xor    r9d,r9d
xor    r8d,r8d
lea    rdx,[rip+...]
call   [CryptHashData]
```

Prototype:

```c
BOOL CryptHashData(
    HCRYPTHASH hHash,
    const BYTE *pbData,
    DWORD      dwDataLen,
    DWORD      dwFlags
);
```

Mapping:

```text
RCX = hHash
RDX = pbData
R8  = dwDataLen
R9  = dwFlags
```

Ransomware đặt:

```asm
xor r8d, r8d
```

nên:

```text
dwDataLen = 0
```

Có nghĩa là **không có byte dữ liệu nào được đưa vào MD5**.

Vì vậy hash luôn là:

```text
MD5("")
```

Tính:

```bash
printf '' | md5sum
```

Kết quả:

```text
d41d8cd98f00b204e9800998ecf8427e
```

---

# 12. Xác định AES-128

Sau `CryptHashData`:

```asm
mov    edx,0x660e
...
call   [CryptDeriveKey]
```

Prototype:

```c
BOOL CryptDeriveKey(
    HCRYPTPROV hProv,
    ALG_ID     Algid,
    HCRYPTHASH hBaseData,
    DWORD      dwFlags,
    HCRYPTKEY  *phKey
);
```

Constant:

```text
0x660e = CALG_AES_128
```

Với sample này, AES-128 key tạo ra tương ứng với MD5 của chuỗi rỗng:

```text
d41d8cd98f00b204e9800998ecf8427e
```

---

# 13. Xác định AES mode

Sau `CryptDeriveKey`, ransomware gọi `CryptSetKeyParam`.

Lần thứ nhất:

```asm
mov    edx,0x4
lea    r8,[rsp+0x34]
...
call   [CryptSetKeyParam]
```

`0x4` là:

```text
KP_MODE
```

Giá trị tại `[rsp+0x34]` được set trước đó:

```asm
mov DWORD PTR [rsp+0x34],0x1
```

Trong CryptoAPI:

```text
1 = CRYPT_MODE_CBC
```

Do đó:

```text
mode = AES-CBC
```

---

# 14. Xác định IV

Lần gọi `CryptSetKeyParam` thứ hai:

```asm
lea    r8,[rsp+0x50]
mov    edx,0x1
call   [CryptSetKeyParam]
```

`0x1` là:

```text
KP_IV
```

Trước đó:

```asm
xorps  xmm0,xmm0
movaps XMMWORD PTR [rsp+0x50],xmm0
```

`xorps xmm0,xmm0` zero hóa 128 bit.

Vì vậy IV là:

```text
00000000000000000000000000000000
```

---

# 15. Xác định padding và cách tạo `.enc`

Disassemble hàm mã hóa:

```bash
objdump -d -Mintel \
  --disassemble='encrypt_file.isra.0' \
  ProtonVPN_x64final.exe
```

Ta thấy ransomware cấp phát:

```asm
lea edx,[rax+0x10]
```

tức:

```text
file_size + 16
```

Sau đó gọi:

```asm
mov    r8d,0x1
...
call   [CryptEncrypt]
```

Trong `CryptEncrypt`, tham số thứ ba là `Final`, nên:

```text
Final = TRUE
```

CryptoAPI sẽ padding block cuối; đối với AES-CBC đây tương thích với PKCS#7 block padding.

Sau đó binary dùng format string:

```text
%s.enc
```

Cuối cùng:

```asm
call [WriteFile]
...
call [DeleteFileA]
```

Pseudo-code:

```c
read(original_file);

ciphertext = AES_128_CBC_Encrypt(
    plaintext,
    key = MD5(""),
    iv = 0x00000000000000000000000000000000,
    padding = PKCS#7
);

write(original_file + ".enc", ciphertext);
delete(original_file);
```

---

# 16. Tổng hợp crypto parameters

```text
Hash algorithm : MD5
Hash input     : empty string / 0 bytes

MD5("")        : d41d8cd98f00b204e9800998ecf8427e

Cipher         : AES-128
Mode           : CBC
Key            : d41d8cd98f00b204e9800998ecf8427e
IV             : 00000000000000000000000000000000
Padding        : PKCS#7
Output         : <original filename>.enc
```

Lỗi thiết kế chí mạng của ransomware là:

> Key hoàn toàn cố định vì `CryptHashData()` được gọi với `dwDataLen = 0`.

Không có password, machine ID, random secret hay victim-specific key nào tham gia.

---

# 17. Giải mã `recovery_codes.txt.enc`

Dùng OpenSSL:

```bash
openssl enc -d -aes-128-cbc \
  -K d41d8cd98f00b204e9800998ecf8427e \
  -iv 00000000000000000000000000000000 \
  -in E/recovery_codes.txt.enc \
  -out recovery_codes.txt
```

Đọc kết quả:

```bash
cat recovery_codes.txt
```

Ta nhận được:

```text
2FA recovery codes
00000-00000
00001-00007
00002-00014
00003-00021
00004-00028
00005-00035
00006-00042
00007-00049
vault-recovery: H7CTF{750b6f18160c332f9f2b}
```

Flag:

```text
H7CTF{750b6f18160c332f9f2b}
```

---

# 18. Giải mã toàn bộ ổ E:

```bash
mkdir -p decrypted_E

KEY='d41d8cd98f00b204e9800998ecf8427e'
IV='00000000000000000000000000000000'

for f in E/*.enc; do
    name="$(basename "$f" .enc)"

    openssl enc -d -aes-128-cbc \
      -K "$KEY" \
      -iv "$IV" \
      -in "$f" \
      -out "decrypted_E/$name"
done
```

Ta khôi phục được:

```text
decrypted_E/Q3_financials.xlsx
decrypted_E/board_minutes.docx
decrypted_E/id_scan_cfo.png
decrypted_E/wallet.dat
decrypted_E/master_password.kdbx
decrypted_E/recovery_codes.txt
decrypted_E/server_key.pem
```

---

# 19. End-to-end solver

Dưới đây là script tự động hóa gần như toàn bộ bài.

Yêu cầu:

- Python 3 standard library
- `openssl` trong `$PATH`

Lưu thành `solve.py` cạnh file `IR-DESKTOP-M-HALE.zip`.

```python
#!/usr/bin/env python3

import hashlib
import sqlite3
import subprocess
import zipfile
from pathlib import Path

IMAGE = Path("IR-DESKTOP-M-HALE.zip")
WORK = Path("work")
WORK.mkdir(exist_ok=True)

DLL_MEMBER = "Program Files/Avast Software/Avast/aswntsqlite.dll"
VAULT_MEMBER = (
    "ProgramData/Avast Software/Avast/chest/"
    "$AV_ASW/$VAULT/vault.db"
)

VAULT_KEY_OFFSET = 0x1E60
VAULT_KEY_SIZE = 0x4000

with zipfile.ZipFile(IMAGE) as z:
    dll = z.read(DLL_MEMBER)
    vault = z.read(VAULT_MEMBER)

    for member in z.namelist():
        if member.startswith("E/") and member.endswith(".enc"):
            z.extract(member, WORK)

# ---------------------------------------------------------
# 1. Decrypt Avast vault.db
# ---------------------------------------------------------

vault_key = dll[
    VAULT_KEY_OFFSET:
    VAULT_KEY_OFFSET + VAULT_KEY_SIZE
]

vault_plain = bytes(
    b ^ vault_key[i % len(vault_key)]
    for i, b in enumerate(vault)
)

assert vault_plain.startswith(b"SQLite format 3\x00")

vault_out = WORK / "vault_decrypted.db"
vault_out.write_bytes(vault_plain)

print(f"[+] Decrypted Avast vault: {vault_out}")

# ---------------------------------------------------------
# 2. Recover ransomware
# ---------------------------------------------------------

con = sqlite3.connect(vault_out)

rows = con.execute(
    "SELECT id, filename, virus, size FROM vault"
).fetchall()

print("[+] Vault entries:")
for row in rows:
    print("   ", row)

ransom_stream_id = con.execute(
    "SELECT crossRef.streamId "
    "FROM vault "
    "JOIN crossRef ON vault.id = crossRef.vaultid "
    "WHERE vault.filename LIKE '%ProtonVPN_x64final.exe'"
).fetchone()[0]

ransomware = con.execute(
    "SELECT data FROM stream WHERE streamId = ?",
    (ransom_stream_id,)
).fetchone()[0]

ransom_path = WORK / "ProtonVPN_x64final.exe"
ransom_path.write_bytes(ransomware)

print(f"[+] Recovered ransomware: {ransom_path}")
print(
    "[+] Ransomware SHA256:",
    hashlib.sha256(ransomware).hexdigest()
)

# ---------------------------------------------------------
# 3. Reconstruct crypto parameters
# ---------------------------------------------------------

# CryptHashData(..., dwDataLen=0, ...)
aes_key = hashlib.md5(b"").digest()

# KP_IV points to a zeroed 16-byte buffer
iv = bytes(16)

print("[+] AES key:", aes_key.hex())
print("[+] AES IV :", iv.hex())

# ---------------------------------------------------------
# 4. Decrypt E:\\*.enc using OpenSSL
# ---------------------------------------------------------

encrypted_dir = WORK / "E"
output_dir = WORK / "decrypted_E"
output_dir.mkdir(exist_ok=True)

for src in encrypted_dir.glob("*.enc"):
    dst = output_dir / src.name.removesuffix(".enc")

    cmd = [
        "openssl",
        "enc",
        "-d",
        "-aes-128-cbc",
        "-K",
        aes_key.hex(),
        "-iv",
        iv.hex(),
        "-in",
        str(src),
        "-out",
        str(dst),
    ]

    subprocess.run(cmd, check=True)
    print(f"[+] Decrypted {src.name} -> {dst.name}")

# ---------------------------------------------------------
# 5. Print flag file
# ---------------------------------------------------------

recovery = output_dir / "recovery_codes.txt"

if recovery.exists():
    print()
    print("[+] recovery_codes.txt:")
    print(recovery.read_text(errors="replace"))
```

Chạy:

```bash
python3 solve.py
```

Output cuối sẽ chứa:

```text
[+] AES key: d41d8cd98f00b204e9800998ecf8427e
[+] AES IV : 00000000000000000000000000000000

vault-recovery: H7CTF{750b6f18160c332f9f2b}
```

---

# 20. Các dấu hiệu quan trọng cần nhận ra

## Clue 1 — `index.xml`

```text
Win32:RansomX-gen [Ransom]
ProtonVPN_x64final.exe
```

Cho biết ransomware từng bị Avast quarantine.

## Clue 2 — `aswntsqlite.dll`

Export:

```text
aswNtSqliteVaultKey
```

gợi ý key của `vault.db`.

## Clue 3 — `vault.db`

Sau XOR xuất hiện:

```text
SQLite format 3
```

xác nhận cách giải đúng.

## Clue 4 — `crossRef`

```text
vault id 2 -> stream id 2
```

cho phép lấy đúng binary ransomware.

## Clue 5 — CryptoAPI imports

```text
CryptCreateHash
CryptHashData
CryptDeriveKey
CryptSetKeyParam
CryptEncrypt
```

chỉ thẳng tới logic mã hóa.

## Clue 6 — `CryptHashData(..., length=0)`

Đây là bug quyết định toàn bài:

```text
hash input = empty
```

nên key không bí mật.

---

# 21. Tại sao challenge khó?

Bài không khó ở riêng AES mà khó vì phải nối nhiều lớp forensic/reversing:

```text
Triage filesystem
      ↓
Avast metadata
      ↓
Custom-obfuscated SQLite vault
      ↓
PE export / section / RVA analysis
      ↓
Recover BLOB from SQLite
      ↓
Windows x64 reversing
      ↓
Windows CryptoAPI constants
      ↓
AES key derivation
      ↓
Decrypt evidence
      ↓
Flag
```

Nếu chỉ nhìn các file `.enc` thì gần như không có dữ liệu để brute-force.

Mấu chốt là hiểu câu:

```text
Whatever froze the assets left a copy of itself behind.
```

Binary ransomware nằm trong quarantine và chính binary đó cung cấp toàn bộ thông tin cần thiết để giải mã.

---

# 22. Flag

```text
H7CTF{750b6f18160c332f9f2b}
```

---

# 23. Quick command reference

```bash
# Extract challenge
unzip IR-DESKTOP-M-HALE.zip -d case
cd case

# Find ransomware metadata
cat 'ProgramData/Avast Software/Avast/chest/index.xml'

# Inspect Avast DLL exports
objdump -x 'Program Files/Avast Software/Avast/aswntsqlite.dll' \
  | grep -A25 -i 'Export Table'

# Show key boundaries
nm -n 'Program Files/Avast Software/Avast/aswntsqlite.dll' \
  | grep -A5 -B5 aswNtSqliteVaultKey

# Show PE sections
objdump -h 'Program Files/Avast Software/Avast/aswntsqlite.dll'

# Analyze ransomware imports
objdump -p ProtonVPN_x64final.exe \
  | grep -E 'Crypt|CreateFile|ReadFile|WriteFile|DeleteFile'

# Disassemble main
objdump -d -Mintel \
  --disassemble=main \
  ProtonVPN_x64final.exe

# Disassemble encryption function
objdump -d -Mintel \
  --disassemble='encrypt_file.isra.0' \
  ProtonVPN_x64final.exe

# Derive broken fixed key
printf '' | md5sum

# Decrypt flag file
openssl enc -d -aes-128-cbc \
  -K d41d8cd98f00b204e9800998ecf8427e \
  -iv 00000000000000000000000000000000 \
  -in E/recovery_codes.txt.enc
```

---

## Integrity hashes

```text
IR-DESKTOP-M-HALE.zip
SHA256:
e41b0b0cf170642eaf5786538b21cfb0ccb8ef4bc624bcfaa159783625317c74

aswntsqlite.dll
SHA256:
fa43405eada89bddb322f66f7b11493b5314994e201d3943969b481117e2f740

vault_decrypted.db
SHA256:
8790bd92a6d1a026d24236fb07bdf1bc742547348dfc98025a7144a5a52d7bdb

ProtonVPN_x64final.exe
SHA256:
4f8f3dc93e50bd3a78b6a478a70c5b80f8746abaeab4c550ca88fd6c11d2b9d1
```

---

**Summary:** Ta khôi phục Avast quarantine database bằng static XOR key lấy từ `aswntsqlite.dll`, trích mẫu ransomware `ProtonVPN_x64final.exe`, reverse Windows CryptoAPI và phát hiện `CryptHashData()` được gọi với độ dài bằng 0. Vì vậy ransomware dùng key AES cố định tương ứng với `MD5("")`, cho phép giải mã toàn bộ ổ `E:` và lấy flag.
