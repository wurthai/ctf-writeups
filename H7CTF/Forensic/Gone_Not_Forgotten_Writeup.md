# H7CTF 2026 – Gone Not Forgotten

- **Category:** Forensics
- **Difficulty:** Medium
- **Points:** 63
- **Challenge file:** `evidence.zip`
- **Flag:** `H7CTF{7adf9695fb655c752810}`

---

## 1. Challenge description

> A phone lands on the evidence bench for a harassment case, and the suspect is adamant they never sent anything ugly. Nova Messenger agrees with them: nothing there.
>
> Deleting a thing and being rid of it were never the same move.

Tên bài **Gone Not Forgotten** và câu cuối là hint rất rõ: dữ liệu đã bị xóa khỏi ứng dụng nhưng có thể **chưa bị xóa vật lý** khỏi nơi lưu trữ.

Với ứng dụng nhắn tin trên mobile, vị trí đầu tiên nên kiểm tra là database SQLite. Khi một row bị `DELETE`, SQLite không nhất thiết xóa sạch toàn bộ byte của record ngay lập tức. Cell cũ có thể trở thành **freeblock** và phần payload vẫn tồn tại cho tới khi vùng đó bị ghi đè.

---

## 2. Giải nén evidence

```bash
unzip evidence.zip -d evidence
cd evidence
find . -maxdepth 2 -type f -ls
```

Ta thu được hai artefact:

```text
messages.db
secure.xml
```

Kích thước thực tế:

```text
messages.db   12288 bytes
secure.xml      255 bytes
```

`messages.db` là SQLite database, còn `secure.xml` trông giống file SharedPreferences/configuration của ứng dụng Android.

---

## 3. Phân tích `secure.xml`

```bash
cat secure.xml
```

Nội dung:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="obfuscation_key">n0v4ch4t</string>
    <string name="stored_body_encoding">hex(xor(body, obfuscation_key))</string>
    <boolean name="biometric_lock" value="true" />
</map>
```

Hai dòng quan trọng nhất:

```text
obfuscation_key      = n0v4ch4t
stored_body_encoding = hex(xor(body, obfuscation_key))
```

Nghĩa là một message body đặc biệt được lưu theo công thức:

```text
ciphertext = hex(XOR(plaintext, "n0v4ch4t"))
```

Vì vậy nếu lấy được chuỗi hex bị xóa trong database, chỉ cần:

1. `bytes.fromhex()`
2. XOR từng byte với key `n0v4ch4t` theo dạng lặp
3. Decode kết quả về text

---

## 4. Kiểm tra SQLite database

Nếu máy có `sqlite3`:

```bash
sqlite3 messages.db
```

Trong SQLite shell:

```sql
.tables
.schema messages
SELECT * FROM messages;
```

Schema:

```sql
CREATE TABLE messages(
    _id INTEGER PRIMARY KEY,
    thread TEXT,
    sender TEXT,
    ts INTEGER,
    body TEXT
);
```

Các row còn sống:

```text
1 | general | alice   | 1710001000000 | lunch at 1?
2 | general | bob     | 1710001100000 | sure, the usual spot
3 | general | alice   | 1710001200000 | cool, see you
5 | ops     | mallory | 1710002050000 | burn this after you read it
6 | general | bob     | 1710002100000 | anyone seen the build?
7 | general | carol   | 1710002200000 | ci is green now
```

Điểm đáng chú ý:

```text
1, 2, 3, [4 missing], 5, 6, 7
```

Row `_id = 4` đã biến mất.

Đây gần như chắc chắn là message mà challenge muốn chúng ta khôi phục.

Có thể kiểm tra bằng Python nếu không có binary `sqlite3`:

```python
import sqlite3

con = sqlite3.connect("messages.db")
cur = con.cursor()

print(cur.execute(
    "SELECT sql FROM sqlite_master WHERE name='messages'"
).fetchone()[0])

for row in cur.execute(
    "SELECT _id, thread, sender, ts, body FROM messages ORDER BY _id"
):
    print(row)
```

---

## 5. Kiểm tra page layout của SQLite

Một số thông tin database:

```sql
PRAGMA page_size;
PRAGMA page_count;
PRAGMA freelist_count;
```

Kết quả:

```text
page_size      = 4096
page_count     = 3
freelist_count = 0
```

Lưu ý `freelist_count = 0` **không có nghĩa** không tồn tại deleted data.

`freelist_count` đếm các **page hoàn chỉnh** nằm trên freelist. Một record bị xóa bên trong một B-tree page có thể chỉ tạo thành **freeblock trong page**, hoàn toàn không làm tăng `PRAGMA freelist_count`.

Database có kích thước:

```text
3 × 4096 = 12288 bytes
```

Page 3 bắt đầu tại file offset:

```text
(page_number - 1) × page_size
= (3 - 1) × 4096
= 8192
= 0x2000
```

---

## 6. Parse header của page 3

SQLite table leaf page có page type `0x0D`.

Các field đầu page header:

| Offset trong page | Size | Ý nghĩa |
|---|---:|---|
| `0x00` | 1 | Page type |
| `0x01` | 2 | Offset của first freeblock |
| `0x03` | 2 | Number of cells |
| `0x05` | 2 | Start of cell content area |
| `0x07` | 1 | Fragmented free bytes |

Parse page 3 cho kết quả:

```text
page type       = 0x0d
first freeblock = 0x0f3a
cell count      = 6
cell content    = 0x0eb0
fragment bytes  = 0
```

`cell count = 6` cũng khớp với 6 messages còn nhìn thấy.

Quan trọng nhất:

```text
first freeblock = 0xF3A
```

Absolute file offset của freeblock:

```text
0x2000 + 0x0F3A = 0x2F3A
```

---

## 7. Carve deleted record từ freeblock

Cấu trúc một SQLite freeblock:

```text
+0x00  2 bytes  offset của freeblock tiếp theo
+0x02  2 bytes  kích thước freeblock hiện tại
+0x04  ...      dữ liệu cũ còn sót lại
```

Tại page-relative offset `0xF3A`, 4 byte đầu là:

```text
00 00 00 4e
```

Giải thích:

```text
00 00 -> không có freeblock tiếp theo
00 4e -> freeblock size = 0x4E = 78 bytes
```

Đây là một chi tiết rất đẹp của challenge: kích thước freeblock **78 byte** chính xác bằng kích thước của deleted cell mà ta có thể reconstruct.

Hexdump vùng đáng chú ý:

```text
00002f30: 6f 75 20 72 65 61 64 20 69 74 00 00 00 4e 13 1b  ou read it...N..
00002f40: 05 79 6f 70 73 6d 61 6c 6c 6f 72 79 01 8e 24 0f  .yopsmallory..$.
00002f50: d0 80 32 36 30 37 33 35 36 30 32 35 31 33 30 33  ..26073560251303
00002f60: 31 35 30 61 35 36 34 66 30 32 35 61 35 64 35 32  150a564f025a5d52
00002f70: 31 36 35 38 30 35 34 33 35 37 35 34 35 64 30 36  1658054357545d06
00002f80: 34 63 35 66 30 30 30 62 ...                       4c5f000b
```

Ta thấy plaintext metadata vẫn còn rõ ràng:

```text
ops
mallory
```

Sau đó là timestamp và một chuỗi hex:

```text
26073560251303150a564f025a5d521658054357545d064c5f000b
```

Đây chính là deleted message body đã được obfuscate.

---

## 8. Vì sao 4 byte đầu deleted cell biến mất?

SQLite table leaf cell có dạng tổng quát:

```text
[varint payload_size]
[varint rowid]
[payload]
```

Payload lại chứa SQLite record header và dữ liệu các cột.

Với deleted row `_id = 4`, ta có thể reconstruct cell cũ thành:

```text
4c 04 06 00 13 1b 05 79 ...
```

Ý nghĩa:

```text
4c       payload size = 0x4C = 76 bytes
04       rowid = 4
06       record header size = 6
00       serial type của INTEGER PRIMARY KEY (_id được biểu diễn qua rowid)
13       TEXT dài 3 byte  -> "ops"
1b       TEXT dài 7 byte  -> "mallory"
05       6-byte signed integer -> timestamp
79       TEXT dài 54 byte -> ciphertext dạng hex
```

Cell total size:

```text
1 byte payload-size
+ 1 byte rowid
+ 76 byte payload
= 78 byte
= 0x4E
```

Chính xác bằng freeblock size.

Khi SQLite biến cell cũ thành freeblock, 4 byte đầu của cell bị ghi đè bằng:

```text
[next freeblock][freeblock size]
```

Do đó:

```text
4c 04 06 00
```

bị thay bằng:

```text
00 00 00 4e
```

Nhưng từ byte tiếp theo:

```text
13 1b 05 79 ...
```

payload cũ vẫn chưa bị overwrite.

Đó là lý do ta vẫn carve được `ops`, `mallory`, timestamp và ciphertext.

---

## 9. Giải mã body

Ciphertext lấy được:

```text
26073560251303150a564f025a5d521658054357545d064c5f000b
```

Key từ `secure.xml`:

```text
n0v4ch4t
```

Script giải mã:

```python
cipher_hex = "26073560251303150a564f025a5d521658054357545d064c5f000b"
key = b"n0v4ch4t"

cipher = bytes.fromhex(cipher_hex)

plain = bytes(
    byte ^ key[i % len(key)]
    for i, byte in enumerate(cipher)
)

print(plain.decode())
```

Output:

```text
H7CTF{7adf9695fb655c752810}
```

---

# 10. Script tự động hoàn chỉnh

Dưới đây là script sử dụng **Python standard library**, không cần cài module ngoài. Nó:

- đọc `secure.xml`
- đọc SQLite page size
- tìm root page của bảng `messages`
- đọc first freeblock
- lấy phần deleted cell còn sót lại
- tìm ciphertext dạng hex
- XOR với key
- in ra flag

```python
#!/usr/bin/env python3

import re
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

DB = Path("messages.db")
XML = Path("secure.xml")

# --------------------------------------------------
# 1. Read obfuscation key
# --------------------------------------------------
root = ET.parse(XML).getroot()

config = {}
for node in root:
    if node.tag == "string":
        config[node.attrib["name"]] = node.text or ""

key = config["obfuscation_key"].encode()
print(f"[+] XOR key: {key!r}")
print(f"[+] Encoding: {config['stored_body_encoding']}")

# --------------------------------------------------
# 2. Query SQLite metadata
# --------------------------------------------------
con = sqlite3.connect(DB)
cur = con.cursor()

page_size = cur.execute("PRAGMA page_size").fetchone()[0]
root_page = cur.execute(
    "SELECT rootpage FROM sqlite_master "
    "WHERE type='table' AND name='messages'"
).fetchone()[0]

print(f"[+] SQLite page size: {page_size}")
print(f"[+] messages root page: {root_page}")

print("[+] Live rows:")
for row in cur.execute(
    "SELECT _id, thread, sender, ts, body "
    "FROM messages ORDER BY _id"
):
    print("   ", row)

con.close()

# --------------------------------------------------
# 3. Parse the table leaf page
# --------------------------------------------------
data = DB.read_bytes()
page_start = (root_page - 1) * page_size
page = data[page_start:page_start + page_size]

page_type = page[0]
if page_type != 0x0D:
    raise RuntimeError(
        f"Expected table leaf page 0x0D, got 0x{page_type:02x}"
    )

first_freeblock = int.from_bytes(page[1:3], "big")
cell_count = int.from_bytes(page[3:5], "big")

print(f"[+] Page type: 0x{page_type:02x}")
print(f"[+] Cell count: {cell_count}")
print(f"[+] First freeblock: 0x{first_freeblock:x}")

if first_freeblock == 0:
    raise RuntimeError("No freeblock found")

# --------------------------------------------------
# 4. Walk freeblocks and look for deleted ciphertext
# --------------------------------------------------
fb = first_freeblock
seen = set()

while fb:
    if fb in seen:
        raise RuntimeError("Freeblock loop detected")
    seen.add(fb)

    next_fb = int.from_bytes(page[fb:fb+2], "big")
    fb_size = int.from_bytes(page[fb+2:fb+4], "big")
    raw = page[fb:fb+fb_size]

    abs_offset = page_start + fb

    print(
        f"[+] Freeblock @ page+0x{fb:x} "
        f"(file+0x{abs_offset:x}), size={fb_size}"
    )

    # The first 4 bytes are freeblock metadata.
    # Search the remaining stale bytes for a long hex string.
    stale = raw[4:]

    match = re.search(rb"[0-9a-fA-F]{40,}", stale)
    if match:
        cipher_hex = match.group().decode()
        print(f"[+] Recovered ciphertext: {cipher_hex}")

        cipher = bytes.fromhex(cipher_hex)
        plain = bytes(
            b ^ key[i % len(key)]
            for i, b in enumerate(cipher)
        )

        try:
            decoded = plain.decode()
        except UnicodeDecodeError:
            decoded = repr(plain)

        print(f"[+] Decrypted: {decoded}")

        flag = re.search(rb"H7CTF\{[^}]+\}", plain)
        if flag:
            print(f"[+] FLAG: {flag.group().decode()}")
            break

    fb = next_fb
else:
    print("[-] Flag not found")
```

Chạy:

```bash
python3 solve.py
```

Kết quả quan trọng:

```text
[+] First freeblock: 0xf3a
[+] Freeblock @ page+0xf3a (file+0x2f3a), size=78
[+] Recovered ciphertext: 26073560251303150a564f025a5d521658054357545d064c5f000b
[+] Decrypted: H7CTF{7adf9695fb655c752810}
[+] FLAG: H7CTF{7adf9695fb655c752810}
```

---

## 11. Một cách nhanh hơn khi thi CTF

Nếu chỉ cần flag và không cần hiểu sâu SQLite ngay từ đầu, có thể triage nhanh bằng `strings`:

```bash
strings -a messages.db
```

Hoặc:

```bash
strings -a messages.db | grep -Ei 'mallory|ops|[0-9a-f]{40,}'
```

Ta có khả năng nhìn thấy chuỗi ciphertext vì các byte của deleted row vẫn nằm nguyên trong file.

Sau đó đọc `secure.xml` để biết key và thuật toán XOR.

Tuy nhiên cách này chỉ là **triage shortcut**. Phân tích freeblock giải thích chính xác **vì sao** dữ liệu đã xóa vẫn tồn tại và là hướng giải forensics đúng bản chất challenge.

---

## 12. Flag

```text
H7CTF{7adf9695fb655c752810}
```

---

## 13. Kết luận / kiến thức rút ra

Bài này minh họa một đặc điểm rất quan trọng trong digital forensics:

> **Logical deletion không đồng nghĩa với physical erasure.**

Một row biến mất khỏi kết quả `SELECT` chưa chắc byte của nó đã biến mất khỏi file SQLite.

Các vị trí thường nên kiểm tra khi cần recover deleted SQLite data gồm:

- freeblocks trong B-tree pages
- unallocated region của page
- freelist pages
- rollback journal (`*-journal`)
- Write-Ahead Log (`*-wal`)
- application cache / backup / temporary files

Trong challenge này không cần WAL hay journal. Deleted record `_id=4` vẫn nằm ngay trong **freeblock của table leaf page**. SQLite chỉ ghi đè 4 byte đầu cell để lưu metadata của freeblock, trong khi phần lớn record body vẫn còn nguyên.

Sau khi carve được ciphertext và kết hợp với cấu hình trong `secure.xml`, XOR lặp với key `n0v4ch4t` cho ra flag.

**Final flag:**

```text
H7CTF{7adf9695fb655c752810}
```
