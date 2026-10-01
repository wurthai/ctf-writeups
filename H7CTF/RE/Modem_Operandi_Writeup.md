# Modem Operandi — H7CTF

**Thể loại:** StaticRev · **Độ khó:** medium · **Điểm:** 63  
**Tệp:** `warden.zip` chứa binary `warden`  
**SHA-256 của `warden`:** `7f5af338d4b0a9b1ebd1fa9625dbf12b34695d900b81ef696b3f457865096a26`

## Kết quả

```text
Licence key: H7X-9F2A-COREKEY
Flag: H7CTF{476f0831f4c4eec5b790}
```

## 1. Chuẩn bị và khảo sát

```bash
unzip warden.zip
chmod +x warden
file warden
sha256sum warden
strings -a -tx warden
readelf -Ws warden
objdump -d -M intel warden > warden.asm
objdump -s -j .rodata warden
```

`warden` là ELF 64-bit PIE x86-64 đã strip. `strings` cho thấy các chuỗi `license key:`, `license rejected`, `license accepted. provisioning: %s`; bảng import có `strlen`, `strncpy`, `MD5`, `AES_set_decrypt_key` và `AES_cbc_encrypt`. Chương trình có nhánh giải mã nội dung sau khi key vượt qua bộ kiểm tra, vì thế chỉ tìm chuỗi bằng `strings` không đủ để lấy flag.

Bạn có thể thấy thông báo lỗi với một key sai:

```bash
./warden AAAAAAAAAAAAAAAA
# license rejected
```

## 2. Tìm điểm bắt đầu của bộ kiểm tra

Do đã strip, `objdump` không đặt tên `main`, nhưng `_start` tại `0x1330` nạp địa chỉ `0x10d0` để gọi `__libc_start_main`. Vùng `0x10d0–0x1307` chính là hàm xử lý chính.

| Địa chỉ tương đối | Vai trò |
| --- | --- |
| `0x10ed–0x1117` | Có `argv[1]` thì copy tối đa 16 byte vào buffer. |
| `0x1119–0x1164` | Không có tham số thì hỏi `license key:`, đọc bằng `fgets`, bỏ xuống dòng. |
| `0x1165–0x1176` | `strlen(key) == 0x10`, tức đúng **16 byte**. |
| `0x117c–0x124a` | Khởi tạo rồi chạy máy ảo (VM) kiểm tra key. |
| `0x124c–0x1258` | Thất bại: in `license rejected`. |
| `0x1262–0x1305` | Thành công: MD5 key, giải mã AES-CBC và in provisioning string. |

Đoạn kiểm tra độ dài:

```asm
116d: call   strlen@plt
1172: cmp    rax,0x10
1176: jne    124c            ; nhảy sang license rejected
```

Đây là **16 byte**, không phải 16 ký tự Unicode bất kỳ. Key của bài chỉ dùng ASCII nên độ dài chuỗi cũng là 16.

## 3. Nhận diện VM từ disassembly

Tại `0x118c`, `r8` trỏ đến `0x20a0` trong `.rodata`, là bytecode. `r10` trỏ đến `0x2060`, là bảng jump table. Vòng lặp lấy opcode, từ chối giá trị lớn hơn 6, rồi nhảy theo jump table:

```asm
118c: lea    r8,[rip+...]     ; 0x20a0: bytecode
1193: lea    r10,[rip+...]    ; 0x2060: jump table
119a: movsxd rax,esi         ; esi = offset hiện tại trong bytecode
11a0: cmp    BYTE PTR [r8+rax],0x6
11a5: ja     124c            ; opcode không hợp lệ -> rejected
11ab: movzx  eax,BYTE PTR [r8+rax]
11b0: movsxd rax,DWORD PTR [r10+rax*4]
11b4: add    rax,r10
11b7: jmp    rax
```

Hai hàm ngắn ở `0x1429` và `0x1445` lần lượt **push** và **pop** một byte trên stack VM nằm trong `.bss` (con trỏ stack tại `0x4080`, vùng byte tại `0x40a0`). Jump table tại `0x2060` ánh xạ các opcode:

| Opcode | Toán hạng | Thao tác VM | Địa chỉ handler |
| --- | --- | --- | --- |
| `00` | Không | Kết thúc; kiểm tra kết quả tích lũy | `0x1247` |
| `01` | Chỉ số byte | Push `key[index]` | `0x11b9` |
| `02` | Byte hằng | Push byte hằng | `0x11ce` |
| `03` | Không | Pop hai byte, push XOR của chúng | `0x11e0` |
| `04` | Không | Pop hai byte, push tổng modulo 256 | `0x11f0` |
| `05` | Số bit | Pop một byte, push kết quả xoay trái `ROL8` | `0x120b` |
| `06` | Byte đích | Pop một byte, so sánh với byte đích; tích lũy kết quả | `0x1221` |

Ví dụ, nhánh `ADD` dùng `add edi,eax` rồi `movzx edi,dil`, nên chỉ giữ 8 bit thấp. Nhánh `CHECK` dùng `sete` rồi `and r9d,eax`: một phép so sánh sai đặt trạng thái cuối về 0, dù VM tiếp tục xử lý các điều kiện sau.

`objdump -s -j .rodata warden` cho biết bytecode bắt đầu tại `0x20a0` và kết thúc bằng opcode `00` tại `0x2160`. Trong binary này, `.rodata` có **file offset trùng địa chỉ tương đối**, nên Python có thể cắt trực tiếp `data[0x20a0:0x2161]`.

## 4. Đảo một đoạn bytecode mẫu

12 byte đầu từ `0x20a0`:

```text
01 00  02 58  03  02 3a  04  05 05  06 49
```

Diễn giải:

```text
PUSH_KEY 0
PUSH_IMMEDIATE 0x58
XOR
PUSH_IMMEDIATE 0x3a
ADD
ROL 5
CHECK 0x49
```

Vì vậy byte `key[0]` phải thỏa:

```text
ROL8(((key[0] XOR 0x58) + 0x3a) & 0xff, 5) == 0x49
```

Đảo ngược lần lượt `ROL`, phép cộng modulo 256 và `XOR`:

```text
key[0] = ((ROR8(0x49, 5) - 0x3a) & 0xff) XOR 0x58
       = ((0x4a - 0x3a) & 0xff) XOR 0x58
       = 0x48 = 'H'
```

VM lặp mẫu 12 byte này 16 lần, mỗi lần lấy một byte key khác nhau. Bảng dưới đây là các hằng số đọc từ **bytecode thật**; cột cuối tính bằng công thức đảo ở trên:

| `index` | XOR | ADD | ROL | CHECK | Byte khôi phục |
| ---: | ---: | ---: | ---: | ---: | --- |
| 0 | `58` | `3a` | 5 | `49` | `H` |
| 1 | `08` | `af` | 3 | `77` | `7` |
| 2 | `3e` | `4e` | 2 | `d2` | `X` |
| 3 | `db` | `7f` | 4 | `57` | `-` |
| 4 | `61` | `db` | 6 | `cc` | `9` |
| 5 | `98` | `23` | 7 | `80` | `F` |
| 6 | `f0` | `44` | 2 | `18` | `2` |
| 7 | `d0` | `66` | 1 | `ef` | `A` |
| 8 | `d9` | `c0` | 3 | `a5` | `-` |
| 9 | `a8` | `f4` | 3 | `fe` | `C` |
| 10 | `52` | `df` | 1 | `f9` | `O` |
| 11 | `d8` | `5f` | 5 | `3d` | `R` |
| 12 | `de` | `5b` | 1 | `ed` | `E` |
| 13 | `9c` | `94` | 6 | `da` | `K` |
| 14 | `32` | `0f` | 1 | `0d` | `E` |
| 15 | `b1` | `23` | 1 | `16` | `Y` |

Ghép theo chỉ số, ta có `H7X-9F2A-COREKEY`.

## 5. Script tự động khôi phục và kiểm tra key

Lưu thành `solve.py` bên cạnh `warden`. Script đọc bytecode trực tiếp từ binary, tách các phép kiểm tra, đảo công thức và chạy lại các lệnh VM bằng Python để xác nhận:

```python
#!/usr/bin/env python3
from pathlib import Path
import sys

binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'warden')
data = binary.read_bytes()
code = data[0x20A0:0x2161]


def rol8(x, n):
    n &= 7
    return ((x << n) | (x >> ((8 - n) & 7))) & 0xFF


def ror8(x, n):
    n &= 7
    return ((x >> n) | (x << ((8 - n) & 7))) & 0xFF


# Parse opcode và toán hạng, gom các lệnh đến mỗi CHECK thành một nhóm.
programs = []
group = []
pc = 0
while pc < len(code):
    op = code[pc]
    pc += 1
    if op == 0:
        assert pc == len(code) and not group
        break
    assert 1 <= op <= 6
    arg = None
    if op in (1, 2, 5, 6):
        arg = code[pc]
        pc += 1
    group.append((op, arg))
    if op == 6:
        programs.append(group)
        group = []

assert len(programs) == 16
key = [None] * 16
pattern = [1, 2, 3, 2, 4, 5, 6]

for program in programs:
    assert [op for op, _ in program] == pattern
    index = program[0][1]
    xor_value = program[1][1]
    add_value = program[3][1]
    shift = program[5][1]
    expected = program[6][1]
    assert index < 16 and key[index] is None

    # ROL8(((byte XOR xor_value) + add_value) & 255, shift)
    #   == expected
    value = ((ror8(expected, shift) - add_value) & 0xFF) ^ xor_value
    key[index] = value
    print(f'key[{index:2}] = 0x{value:02x} ({chr(value)})')

assert all(x is not None for x in key)
key = bytes(key)

# Chạy lại bytecode trong Python để kiểm tra phép đảo.
for program in programs:
    stack = []
    for op, arg in program:
        if op == 1:
            stack.append(key[arg])
        elif op == 2:
            stack.append(arg)
        elif op == 3:
            b, a = stack.pop(), stack.pop()
            stack.append(a ^ b)
        elif op == 4:
            b, a = stack.pop(), stack.pop()
            stack.append((a + b) & 0xFF)
        elif op == 5:
            stack.append(rol8(stack.pop(), arg))
        elif op == 6:
            assert stack.pop() == arg
    assert not stack

print('Licence key:', key.decode('ascii'))
```

Chạy:

```bash
python3 solve.py ./warden
# ...
# Licence key: H7X-9F2A-COREKEY
```

## 6. Giải mã provisioning string và lấy flag

Sau khi VM chấp nhận key, hàm chính gọi `MD5(key, 16, ...)` tại `0x1277`, đặt khóa giải mã AES-128 tại `0x129d`, rồi gọi `AES_cbc_encrypt` ở chế độ giải mã (`r9d = 0`) cho 32 byte tại `0x2080`. IV 16 byte được đặt bằng 0. Công thức:

```text
aes_key = MD5(b'H7X-9F2A-COREKEY')
        = 8ca31a6e2c0d79de68907c78a5e6405f
```

Ciphertext trong `.rodata`:

```text
ab 7a cb 5a b6 fb 1f 2a 82 42 ec c6 26 65 45 03
5d 16 df 91 da 6a bb 10 04 cc 19 8d 0a f8 66 2b
```

Cách xác nhận trực tiếp bằng binary:

```bash
./warden 'H7X-9F2A-COREKEY'
# license accepted. provisioning: H7CTF{476f0831f4c4eec5b790}
```

Nếu muốn kiểm tra tĩnh riêng bước AES bằng OpenSSL CLI:

```bash
python3 - <<'PY' | openssl enc -d -aes-128-cbc \
  -K 8ca31a6e2c0d79de68907c78a5e6405f \
  -iv 00000000000000000000000000000000
from pathlib import Path
import sys
sys.stdout.buffer.write(Path('warden').read_bytes()[0x2080:0x20A0])
PY
# H7CTF{476f0831f4c4eec5b790}
```

Plaintext gồm flag và 5 byte padding PKCS#7 (`05 05 05 05 05`). Trong chương trình, byte cuối được dùng để đặt dấu kết thúc chuỗi `\0` trước khi in.

## Kết luận

Trọng tâm bài là nhận ra vòng lặp tại `0x119a` là một trình thông dịch bytecode. Mỗi nhóm lệnh biến đổi độc lập một byte key bằng XOR, cộng modulo 256 và xoay trái; đọc các hằng số rồi đảo phép biến đổi sẽ khôi phục đủ 16 byte. Key hợp lệ sau đó tạo khóa AES từ MD5 và mở provisioning string chứa flag.
