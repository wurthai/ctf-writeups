# Rust in Peace — write-up StaticRev

## Thông tin bài

- **Tên:** Rust in Peace
- **Loại:** Static Reverse Engineering
- **Độ khó:** Medium (63 điểm)
- **Tệp được cung cấp:** `ferric(2).zip`, chứa ELF `ferric`
- **Mục tiêu:** Tìm licence hợp lệ để chương trình in token.

> Các địa chỉ và kết quả dưới đây được kiểm tra trên chính binary trong `ferric(2).zip`. Đây là bài phân tích một chương trình CTF chạy cục bộ; không cần dịch vụ từ xa.

## 1. Giải nén và khảo sát

```bash
unzip 'ferric(2).zip'
file ferric
chmod +x ferric
./ferric
printf 'test\n' | ./ferric
```

`file` cho biết đây là **ELF 64-bit x86-64, PIE, dynamically linked, stripped**. Chạy thử cho thấy chương trình đọc key từ stdin:

```text
license: invalid license
```

Chuỗi phản hồi nằm trong `.rodata`; ta tìm địa chỉ của nó và chỗ tham chiếu đến nó:

```bash
strings -a -t x ferric | grep -E 'license:|invalid license'
objdump -d -M intel ferric | grep -E '5050|52c0'
```

Kết quả đáng chú ý:

```text
5050 invalid license
52c0 license: ...
```

Trong `.text`, `0x158a0` tham chiếu chuỗi nhắc nhập licence ở `0x52c0`, còn `0x15c55` tham chiếu chuỗi `invalid license` ở `0x5050`. Lần ngược từ đó xác định được hàm xử lý chính gần `0x157e0`. Vì binary là PIE, các số trên là **địa chỉ tương đối trong ELF** mà `objdump` hiển thị; giá trị lúc chạy còn phụ thuộc base address do ASLR.

## 2. Tìm phép kiểm tra key

Xem vùng có nhánh thất bại:

```bash
objdump -d -M intel \
  --start-address=0x15c39 --stop-address=0x15d97 ferric
```

Sau khi xử lý khoảng trắng đầu/cuối của chuỗi nhập, chương trình sao chép nội dung key. Nó yêu cầu **đúng 16 byte**:

```asm
15ce1: cmp    rbx,0x10          ; độ dài key == 16?
15ce5: jne    15d90             ; sai độ dài -> invalid license
```

Trong vòng lặp, chỉ số `r9` đi từ `0` đến `15`. Các địa chỉ bảng được nạp trước vòng lặp:

```asm
15cee: lea    rax,[rip+...]     ; 0x5140: bảng XOR
15cfa: lea    rsi,[rip+...]     ; 0x5180: số bit xoay
15d06: lea    r8,[rip+...]      ; 0x51b0: bảng cộng
15d17: lea    r11,[rip+...]     ; 0x52b0: kết quả mong đợi
```

Đoạn kiểm tra một byte (lược bỏ các lệnh chuyển dữ liệu qua stack):

```asm
15d36: movzx  r15d,BYTE PTR [r14+r9] ; key[i]
15d3b: movzx  ecx,BYTE PTR [rax+r9] ; X[i]
15d56: xor    r15b,BYTE PTR [rsp+0xe]
15d5b: movzx  ecx,BYTE PTR [rsp+0xf] ; R[i]
15d60: rol    r15b,cl               ; xoay trái 8 bit
15d63: add    r15b,BYTE PTR [rsp+0x28] ; A[i], phép cộng modulo 256
15d6d: movzx  ecx,BYTE PTR [r11+r9] ; T[i]
15d7e: cmp    cl,BYTE PTR [rsp+0x30]
15d82: je     15d30                 ; bằng thì xét byte kế tiếp
15d84: xor    ebp,ebp               ; sai -> invalid license
```

Đặt `X`, `R`, `A`, `T` là bốn bảng trên, `ROL8` là xoay trái một byte. Điều kiện tại từng vị trí `i` là:

```text
T[i] = (ROL8(key[i] XOR X[i], R[i]) + A[i]) mod 256
```

Mỗi vị trí độc lập, vì vậy ta đảo phép toán để lấy key trực tiếp, không cần brute force:

```text
key[i] = ROR8((T[i] - A[i]) mod 256, R[i]) XOR X[i]
```

`ROR8` là xoay phải trên 8 bit. Cần giữ `& 0xff` sau phép trừ để mô phỏng số nguyên một byte.

## 3. Lấy bốn bảng hằng từ binary

Xem bytes tại các offset tương ứng trong `.rodata`:

```bash
od -Ax -tx1 -j 0x5140 -N 16 ferric
od -Ax -tx1 -j 0x5180 -N 16 ferric
od -Ax -tx1 -j 0x51b0 -N 16 ferric
od -Ax -tx1 -j 0x52b0 -N 16 ferric
```

Trong binary này, `.rodata` có địa chỉ ảo bằng file offset ở các vị trí trên. Với một binary khác, phải tra `readelf -S` để quy đổi địa chỉ ảo sang file offset, không được mặc định chúng bằng nhau.

| Bảng | Offset | 16 byte (hex) |
| --- | ---: | --- |
| `X` — XOR | `0x5140` | `c4 b3 73 91 52 10 a7 94 88 3d b0 65 77 fe f1 f0` |
| `R` — xoay trái | `0x5180` | `07 06 06 02 05 05 04 03 04 01 06 03 03 02 06 07` |
| `A` — cộng | `0x51b0` | `9c 45 df 14 7c c2 56 e1 59 be 23 24 19 3d df 09` |
| `T` — đích | `0x52b0` | `dd 02 27 23 df 2c fe 17 36 9a 5c 66 fa 2b 09 e9` |

## 4. Script khôi phục licence

Lưu nội dung sau thành `solve.py` cùng thư mục với `ferric`, rồi chạy `python3 solve.py`:

```python
#!/usr/bin/env python3
from pathlib import Path

blob = Path('ferric').read_bytes()

# Với ELF này, các địa chỉ .rodata trên cũng là file offset.
X = blob[0x5140:0x5150]
R = blob[0x5180:0x5190]
A = blob[0x51b0:0x51c0]
T = blob[0x52b0:0x52c0]
assert all(len(table) == 16 for table in (X, R, A, T))


def ror8(value, amount):
    amount &= 7
    return ((value >> amount) | (value << (8 - amount))) & 0xff


def rol8(value, amount):
    amount &= 7
    return ((value << amount) | (value >> (8 - amount))) & 0xff


key = bytes(
    ror8((target - addition) & 0xff, rotation) ^ xor_byte
    for xor_byte, rotation, addition, target in zip(X, R, A, T)
)

# Tự kiểm tra cả 16 điều kiện trước khi đưa key cho binary.
assert all(
    ((rol8(key[i] ^ X[i], R[i]) + A[i]) & 0xff) == T[i]
    for i in range(16)
)
print('License key:', key.decode('ascii'))
```

Kết quả:

```text
License key: FERRIC-RUST-KEY1
```

Ví dụ với byte đầu: `X[0]=0xc4`, `R[0]=7`, `A[0]=0x9c`, `T[0]=0xdd`. Ta tính `ROR8((0xdd - 0x9c) & 0xff, 7) XOR 0xc4 = 0x46`, tức chữ `F`. Lặp lại với 15 byte còn lại sẽ tạo ra toàn bộ key.

## 5. Kiểm chứng và lấy flag

Binary nhận licence qua **stdin** tại lời nhắc `license:`:

```bash
printf 'FERRIC-RUST-KEY1\n' | ./ferric
```

Kết quả chạy thực tế:

```text
license: unlocked: H7CTF{3f7b3f564a5524ce863d}
```

Sau khi cả 16 phép so sánh đều đúng, luồng thực thi đi từ `0x15d97` sang nhánh tạo chuỗi `unlocked: ...`; vì vậy key khôi phục bằng phép đảo ở trên được xác nhận bằng chính chương trình.

## Kết quả

```text
Licence: FERRIC-RUST-KEY1
Flag:    H7CTF{3f7b3f564a5524ce863d}
```
