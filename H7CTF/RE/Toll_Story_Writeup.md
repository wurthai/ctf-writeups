# Toll Story – Write-up (DockerRev / Reverse)

**Challenge:** Toll Story  
**Category:** Reverse Engineering (medium)  
**Points:** 63  
**Description:**  
> Toll Story is the admin lane of an internal API gateway. Show it the right token and the booth waves through the cluster bootstrap secret; show it anything else and you get "access denied."  
> There's a toll on this road, and it isn't paid in cash.

Binary: `tollgate` (Go ELF 64-bit, stripped, Go 1.23.12, `-trimpath`)

---

## 1. Initial Reconnaissance

```bash
file tollgate
# ELF 64-bit LSB executable, x86-64, statically linked, stripped

./tollgate
# admin token: access denied

./tollgate anything
# access denied

strings tollgate | grep -E 'access|granted|bootstrap|secret'
# admin token: access denied
# access granted. bootstrap secret:
```

- Không có symbol (stripped).
- Là binary Go (có `.gopclntab`, build ID, `main.main`, `main.unlock`, `main.check`).
- Token được truyền qua `argv[1]`.
- Token đúng → in ra `access granted. bootstrap secret: <secret>`.

---

## 2. Phân tích luồng chương trình (main.main)

Dùng `redress` + parse `.gopclntab` để lấy địa chỉ hàm:

| Hàm          | Địa chỉ   |
|--------------|-----------|
| `main.main`  | `0x498760`|
| `main.unlock`| `0x498600`|

### Logic chính trong `main.main`

1. Nếu `len(os.Args) <= 1` → in `"admin token: access denied"` và thoát.
2. Lấy `argv[1]` → chuyển thành `[]byte`.
3. Nếu `len != 16` → in `"access denied"` + `os.Exit(1)`.
4. **Kiểm tra token** (custom ARX check trên 4 × `uint32`).
5. Nếu pass → gọi `main.unlock(token)`.
6. In `"access granted. bootstrap secret: "` + plaintext trả về từ `unlock`.

---

## 3. Reverse phần kiểm tra token (main.check)

Đoạn code quan trọng (sau khi `len == 16`):

```asm
; rdx = 0, sil = 1 (ban đầu)
; loop 4 lần (i = 0..3)
mov    r9d, [token + i*4]
bswap  r9d
xor    r9d, XOR_TABLE[i]
rol    r9d, ROT_TABLE[i]
add    r9d, ADD_TABLE[i]
cmp    r9d, EXPECT_TABLE[i]
jne    fail          ; sil = 0
```

### Bảng hằng số (từ `.data`)

```text
ROT_TABLE  = [0x16, 0x0c, 0x03, 0x14]   # 22, 12, 3, 20
XOR_TABLE  = [2086338156, 501189851, 2472720933, 2794038474]
ADD_TABLE  = [3024221647, 1069332953, 282001161, 2071941983]
EXPECT     = [2186219843, 2076605618, 1250359118, 1530802222]
```

Mỗi block 4 byte được xử lý **độc lập** → có thể reverse từng block một.

### Script reverse token

```python
import struct

rots   = [0x16, 0x0c, 0x03, 0x14]
xors   = [2086338156, 501189851, 2472720933, 2794038474]
adds   = [3024221647, 1069332953, 282001161, 2071941983]
expects = [2186219843, 2076605618, 1250359118, 1530802222]

def ror(x, n):
    n %= 32
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

token = b''
for i in range(4):
    val = expects[i]
    val = (val - adds[i]) & 0xffffffff
    val = ror(val, rots[i])
    val ^= xors[i]
    val = struct.unpack(">I", struct.pack("<I", val))[0]  # bswap
    token += struct.pack("<I", val)

print(token)          # b'H7-T0LLG4TE-KEY1'
print(token.hex())
```

**Token đúng:** `H7-T0LLG4TE-KEY1`

---

## 4. Phân tích `main.unlock` – giải mã secret

```go
// Pseudocode
func unlock(token []byte) string {
    key := sha256.Sum256(token)           // 32-byte AES key
    block, _ := aes.NewCipher(key[:])
    iv := make([]byte, 16)                // IV = zeros
    mode := cipher.NewCBCDecrypter(block, iv)

    // Ciphertext hard-coded 48 bytes trong .data
    ct := []byte{0x9b,0x76,...}           // 3 AES blocks
    pt := make([]byte, 48)
    mode.CryptBlocks(pt, ct)

    // PKCS#7 unpad
    pad := int(pt[len(pt)-1])
    if pad < 1 || pad > 16 || !bytes.Equal(pt[len(pt)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
        panic(...)
    }
    return string(pt[:len(pt)-pad])
}
```

- Key = `SHA-256(token)`
- Mode = AES-256-CBC
- IV = 16 byte zero
- Ciphertext = 48 byte cố định trong binary
- Sau decrypt → PKCS#7 unpad → chuỗi secret

---

## 5. Khai thác / Lấy flag

```bash
./tollgate 'H7-T0LLG4TE-KEY1'
# access granted. bootstrap secret: H7CTF{9690c80f-12cc-4300-bfbd-f8531228efdb}
```

*(Lưu ý: mỗi bản binary có thể có ciphertext khác nhau → secret khác nhau, nhưng token check giữ nguyên.)*

---

## 6. Tóm tắt kỹ thuật

| Thành phần          | Chi tiết                                      |
|---------------------|-----------------------------------------------|
| Ngôn ngữ            | Go 1.23.12 (static, stripped)                 |
| Token length        | Chính xác 16 byte                             |
| Validation          | ARX (bswap → xor → rol → add) trên 4 uint32   |
| Crypto              | AES-256-CBC, key = SHA-256(token), IV = 0     |
| Padding             | PKCS#7                                        |
| Output              | `access granted. bootstrap secret: <flag>`    |

---

## 7. Công cụ sử dụng

- `strings`, `readelf`, `objdump`, `gdb`
- `redress` (goretk) – lấy thông tin package / source projection
- Parse thủ công `.gopclntab` (magic `0xfffffff1`) để recover địa chỉ hàm
- Python + `cryptography` / `struct` để reverse ARX + verify AES

---

**Flag:** `H7CTF{9690c80f-12cc-4300-bfbd-f8531228efdb}`
