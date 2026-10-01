# Constraint Yourself — H7CTF 2026

**Thể loại:** DockerRev · **Độ khó:** medium · **Điểm:** 63  
**File phân tích:** `cipherlock (1)` (ELF 64-bit, x86-64, PIE, stripped)  
**SHA-256:** `1bd6fc741124a8191d4b274ec998513bd859d8f330e89b0d8f1793b3ce821e86`

## Kết quả

```text
Key : S4T-C0NSTR4INT!7
Flag: H7CTF{313bf316-7351-448d-a9ff-569ac32e0cce}
```

## 1. Khảo sát ban đầu

Các lệnh dưới đây giả định bạn đặt file vào thư mục hiện tại với tên `cipherlock (1)`:

```bash
file 'cipherlock (1)'
sha256sum 'cipherlock (1)'
strings -a -tx 'cipherlock (1)'
readelf -Ws 'cipherlock (1)'
objdump -d -M intel 'cipherlock (1)' > cipherlock.asm
```

`file` cho biết đây là ELF 64-bit đã strip. Các chuỗi đáng chú ý:

```text
key:
cipherlock: denied
cipherlock: open. %s
```

Danh sách hàm import có `strlen`, `MD5`, `AES_set_decrypt_key` và `AES_cbc_encrypt`. Suy ra chương trình kiểm tra đầu vào rồi dùng key hợp lệ để giải mã phần thưởng. `strings` không hiện flag vì flag nằm trong dữ liệu mã hóa.

File đính kèm có thể chưa có quyền chạy. Để thử mà không sửa bản gốc:

```bash
cp 'cipherlock (1)' ./cipherlock
chmod u+x ./cipherlock
./cipherlock AAAAAAAAAAAAAAAA
# cipherlock: denied
```

## 2. Xác định luồng kiểm tra

Mở `cipherlock.asm`, xem vùng `.text` từ địa chỉ `0x1180`. Các địa chỉ trong bài viết là **địa chỉ tương đối của ELF**, không phải địa chỉ tuyệt đối lúc chạy PIE.

- `0x11bf–0x11d2`: nếu có tham số dòng lệnh, copy tối đa 16 byte từ `argv[1]`.
- `0x11d4–0x121a`: nếu không có tham số, đọc tối đa 16 byte bằng `fgets`, rồi bỏ ký tự xuống dòng.
- `0x121b–0x1227`: gọi `strlen` và yêu cầu độ dài **đúng 16**.
- `0x122d–0x12a9`: ba vòng lặp kiểm tra các quan hệ giữa các byte.
- `0x12ab–0x12bb`: sai bất kỳ điều kiện nào thì in `cipherlock: denied`.
- `0x12c5–0x136b`: đúng hết thì tính MD5 của 16 byte key, dùng kết quả làm khóa AES-128 để giải mã 48 byte dữ liệu, rồi in `cipherlock: open. %s`.

Điểm dễ bỏ sót: ba vòng lặp cùng cập nhật biến trạng thái `edx` bằng `cmovne edx, esi`, trong đó `esi = 0`. Chương trình vẫn đi qua tất cả các vòng, nhưng chỉ một phép so sánh sai cũng khiến `edx` bằng 0 và bị từ chối.

## 3. Trích hằng số và viết lại các ràng buộc

Vùng `.rodata` bắt đầu ở offset file `0x2000`, trùng với địa chỉ tương đối tại đây. Có thể trích ba bảng kiểm tra bằng Python:

```bash
python3 - <<'PY'
from pathlib import Path

data = Path('cipherlock (1)').read_bytes()
for name, off, size in [
    ('ROL+ADD', 0x2070, 16),
    ('MUL',     0x2080,  8),
    ('XOR',     0x2090, 16),
]:
    print(f'{name:7s} 0x{off:x}: {data[off:off + size].hex()}')
PY
```

Kết quả:

```text
ROL+ADD 0x2070: caeff5bd6cb5bbe8f6b3d89da6f636fc
MUL     0x2080: dcc4904ae8d49817
XOR     0x2090: 7e77646310641c671d1c606879071563
```

Đặt `k[i]` là byte thứ `i` của key, với `0 ≤ i < 16`. Từ disassembly ta được:

### Điều kiện XOR — `0x123d–0x125a`

```text
k[i] XOR k[(i + 3) mod 16] = XOR_TABLE[i]
```

Trong assembly, `lea ecx,[rax+0x3]` cộng 3, `and ecx,0xf` lấy modulo 16, rồi `xor cl,[rbx+rax]` thực hiện phép XOR.

### Điều kiện nhân — `0x1267–0x127b`

```text
(k[2*j] * k[2*j + 1]) mod 256 = MUL_TABLE[j],  0 ≤ j < 8
```

Lệnh `mul BYTE PTR [...]` tạo kết quả 16 bit trong `AX`; chương trình chỉ so sánh `AL`, tức **8 bit thấp**. Nếu so sánh tích nguyên không lấy modulo 256, script sẽ loại nhầm key đúng.

### Điều kiện xoay và cộng — `0x1288–0x12a9`

```text
(ROL8(k[i], 3) + k[(i + 5) mod 16]) mod 256 = ROL_ADD_TABLE[i]
```

`rol cl,0x3` xoay trái trong phạm vi 8 bit; `add cl,...` cũng tự tràn theo modulo 256.

## 4. Giải bằng 256 giá trị đầu tiên

Chỉ cần chọn `k[0]`. Điều kiện XOR suy ra `k[3]`, rồi `k[6]`, `k[9]`, ... cho đến mọi vị trí. Vì `gcd(3, 16) = 1`, dãy chỉ số nhảy 3 sẽ đi qua đủ 16 vị trí trước khi quay về 0. Thử `k[0]` từ 0 đến 255, kiểm tra tính nhất quán của vòng XOR, rồi lọc bằng hai nhóm còn lại.

Lưu đoạn sau thành `solve.py` trong cùng thư mục với binary:

```python
#!/usr/bin/env python3
from pathlib import Path

data = Path('cipherlock (1)').read_bytes()
rol_add_table = data[0x2070:0x2080]
mul_table = data[0x2080:0x2088]
xor_table = data[0x2090:0x20A0]


def rol8(value, count):
    return ((value << count) | (value >> (8 - count))) & 0xFF


solutions = []

for first in range(256):
    key = [None] * 16
    key[0] = first
    i = 0
    consistent = True

    # Lan truyền k[i+3] = k[i] XOR xor_table[i].
    for _ in range(16):
        next_i = (i + 3) % 16
        value = key[i] ^ xor_table[i]

        if key[next_i] is not None and key[next_i] != value:
            consistent = False
            break

        key[next_i] = value
        i = next_i

    if not consistent or any(value is None for value in key):
        continue

    if not all(
        ((key[2 * j] * key[2 * j + 1]) & 0xFF) == mul_table[j]
        for j in range(8)
    ):
        continue

    if not all(
        ((rol8(key[i], 3) + key[(i + 5) % 16]) & 0xFF)
        == rol_add_table[i]
        for i in range(16)
    ):
        continue

    solutions.append(bytes(key))

print(f'Solutions: {len(solutions)}')
for key in solutions:
    print('Key (ASCII):', key.decode('ascii'))
    print('Key (hex)  :', key.hex())
```

Chạy:

```bash
python3 solve.py
```

Đầu ra:

```text
Solutions: 1
Key (ASCII): S4T-C0NSTR4INT!7
Key (hex)  : 5334542d43304e53545234494e542137
```

Không cần Z3 cho trường hợp này: nhóm XOR tự thu hẹp không gian tìm kiếm còn tối đa 256 key ứng viên.

## 5. Kiểm chứng flag

```bash
./cipherlock 'S4T-C0NSTR4INT!7'
```

Đầu ra thực tế:

```text
cipherlock: open. H7CTF{313bf316-7351-448d-a9ff-569ac32e0cce}
```

Về bước cuối trong binary: `MD5(key, 16, ...)` tạo 16 byte `1cb0462d48162b777e20b6882e4cfed9`. `AES_set_decrypt_key(..., 128, ...)` sử dụng chúng làm khóa AES-128; `AES_cbc_encrypt` giải mã 48 byte ciphertext ở `0x2040` bằng CBC với IV 16 byte bằng 0. Bản thân key là câu trả lời của hệ ràng buộc; flag là plaintext thu được khi chạy nhánh thành công.

## Kết luận

Thử thách giấu flag bằng AES và dùng ba bộ điều kiện byte để kiểm tra key trước khi giải mã. Quan hệ XOR với bước nhảy 3 nối toàn bộ 16 byte thành một chu trình, nên có thể giải rất nhanh bằng cách thử đúng một byte, kiểm tra hai nhóm điều kiện còn lại, rồi chạy binary để lấy flag.
