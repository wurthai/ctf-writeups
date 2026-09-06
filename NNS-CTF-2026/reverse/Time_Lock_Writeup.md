# Writeup - Time Lock

## Challenge Information

-   **Name:** Time Lock
-   **Category:** Reverse Engineering
-   **Difficulty:** Beginner
-   **Author:** hoover
-   **Technique:** LD_PRELOAD Hooking + Reverse Engineering

------------------------------------------------------------------------

## Description

Challenge cung cấp một file ELF x86-64. Chương trình hoạt động như một
"sealed archive":

-   Hỏi ngày hiện tại thông qua thư viện C (`time()`).
-   Chỉ mở khóa khi ngày là **01/01/9999**.
-   Những ngày khác chỉ in ra:

```{=html}
<!-- -->
```
    sealed

Không thể: - Đợi tới năm 9999. - Đổi thời gian hệ thống. - Patch đơn
giản phần kiểm tra ngày.

Lý do là key giải mã flag được tạo dựa trên giá trị thời gian mà chương
trình nhận được.

Mục tiêu là thay thế hàm lấy thời gian bằng một hàm giả.

------------------------------------------------------------------------

# 1. Kiểm tra binary

Sử dụng:

``` bash
file time-lock
```

Kết quả:

    ELF 64-bit LSB executable, x86-64

Kiểm tra thư viện được sử dụng:

``` bash
nm -D time-lock
```

Nhận thấy chương trình import:

    time@GLIBC_2.2.5

=\> Chương trình lấy thời gian thông qua hàm `time()` của libc.

------------------------------------------------------------------------

# 2. Phân tích chương trình

Disassemble:

``` bash
objdump -d -M intel time-lock
```

Tìm thấy lời gọi:

``` asm
call time@plt
```

Sau khi lấy timestamp, chương trình chuyển đổi và kiểm tra ngày.

Điều kiện mở khóa yêu cầu timestamp tương ứng với:

    01/01/9999

------------------------------------------------------------------------

# 3. Ý tưởng khai thác

Linux dynamic linker cho phép chèn thư viện trước libc bằng biến môi
trường:

``` bash
LD_PRELOAD
```

Khi chạy:

``` bash
LD_PRELOAD=./fake.so ./time-lock
```

chương trình sẽ ưu tiên sử dụng hàm `time()` trong thư viện của chúng ta
thay vì libc thật.

------------------------------------------------------------------------

# 4. Tạo fake time library

Tính timestamp của ngày 01/01/9999:

``` python
import datetime
import calendar

ts = calendar.timegm(
    datetime.datetime(
        9999,1,1,
        tzinfo=datetime.timezone.utc
    ).timetuple()
)

print(ts)
```

Kết quả:

    253370764800

Tạo file:

    fake.c

Nội dung:

``` c
#include <time.h>

time_t time(time_t *t)
{
    time_t fake = 253370764800;

    if(t)
        *t = fake;

    return fake;
}
```

Compile:

``` bash
gcc -shared -fPIC fake.c -o fake.so
```

------------------------------------------------------------------------

# 5. Chạy với LD_PRELOAD

Thực thi:

``` bash
LD_PRELOAD=./fake.so ./time-lock
```

Bây giờ chương trình nhận được ngày giả:

    01/01/9999

và vượt qua bước kiểm tra.

------------------------------------------------------------------------

# 6. Phân tích thuật toán giải mã flag

Sau khi bypass date check, chương trình dùng giá trị timestamp để tạo
key.

Trong binary có một đoạn mã dạng:

``` asm
imul
xor
loop
```

Đây là một dạng stream cipher đơn giản.

Key ban đầu:

    0x4db55fbe

Công thức cập nhật:

    key = key * 0x15a4e35 + 1

Mỗi byte flag được giải mã:

    plaintext = ciphertext XOR (key >> 16)

------------------------------------------------------------------------

# 7. Script decrypt

``` python
enc = bytes.fromhex(
"cad01b6ec3ae20e4e9ff988e975381aa"
"580915662e8b5531a7d035cfc24de301"
"3a8b96245cb8c12fd5008cfbd1a800"
)

key = 0x4db55fbe

flag = []

for b in enc:
    key = (key * 0x15a4e35 + 1) & 0xffffffff
    flag.append(b ^ ((key >> 16) & 0xff))

print(bytes(flag).decode())
```

------------------------------------------------------------------------

# 8. Flag

Sau khi decrypt:

    NNS{y0u_c4n_l13_70_4_pr0gr4m_w17h_ld_pr3l04d}

------------------------------------------------------------------------

# 9. Tổng kết kỹ thuật

  Kỹ thuật                  Ý nghĩa
  ------------------------- -----------------------
  ELF analysis              Kiểm tra binary Linux
  objdump                   Reverse assembly
  libc hooking              Thay thế hàm runtime
  LD_PRELOAD                Inject shared library
  Stream cipher reversing   Giải mã flag

------------------------------------------------------------------------

## Bài học

Challenge này giới thiệu một kỹ thuật rất phổ biến trong Linux reverse
engineering:

-   Không nhất thiết phải patch binary.
-   Có thể thay đổi hành vi chương trình bằng cách hook các hàm thư
    viện.
-   `LD_PRELOAD` là công cụ mạnh để debug, pentest và reverse
    engineering.
