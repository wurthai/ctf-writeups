# Open Secret — Reverse Engineering Write-up

## 1. Challenge Information

| | |
|---|---|
| **Challenge** | Open Secret |
| **Category**  | Reverse Engineering |
| **Difficulty**| Beginner |
| **Author**    | hoover |

**Description:**

Challenge cung cấp một file ELF x86-64. Chương trình yêu cầu một license file trước khi chạy.

Đường dẫn license không xuất hiện trong binary và không thể tìm bằng `strings`. Chương trình tự xây dựng đường dẫn trong bộ nhớ rồi gọi trực tiếp kernel syscall để mở file.

**Mục tiêu:**
- Tìm đường dẫn license.
- Tạo file license.
- Chạy lại chương trình để lấy flag.

---

## 2. Initial Recon

Giải nén file:

```bash
tar -xvf rev_open-secret.tar.gz
```

Kiểm tra binary:

```bash
file open-secret
```

Kết quả:

```
ELF 64-bit LSB executable x86-64
```

Chạy thử:

```bash
./open-secret
```

Output:

```
no license
```

---

## 3. Static Analysis

Dùng `strings`:

```bash
strings open-secret
```

Kết quả chỉ có:

```
no license
HOME=
```

Không tìm thấy đường dẫn license. Điều này cho thấy đường dẫn được tạo khi chương trình chạy.

---

## 4. System Call Tracing

Chương trình không sử dụng các hàm thư viện như `open()`, `fopen()`. Nó gọi trực tiếp kernel syscall. Vì vậy `ltrace` không có tác dụng.

Sử dụng:

```bash
strace ./open-secret
```

Quan sát thấy syscall:

```
openat()
```

`openat` có dạng:

```c
openat(dirfd, pathname, flags)
```

Tham số `pathname` chính là file license cần tìm.

---

## 5. Reverse Engineering

Trong binary tìm đoạn gọi syscall:

```asm
mov eax, 257
syscall
```

Trên Linux x86-64, `rax = 257` tương ứng syscall `openat`.

Binary lấy dữ liệu đã mã hóa trong bộ nhớ và giải mã bằng XOR kết hợp LCG. Thuật toán:

```
state = 2
for mỗi byte:
    state = state * 0x19660d + 0x3c6ef35f
    buffer[i] ^= state >> 16
```

Sau khi giải mã thu được:

```
/.config/nns/key
```

Chương trình ghép với biến môi trường `HOME`:

```
/home/<user>/.config/nns/key
```

---

## 6. Creating License File

Tạo file:

```bash
mkdir -p ~/.config/nns
touch ~/.config/nns/key
```

Sau đó chạy lại:

```bash
./open-secret
```

---

## 7. Extracting Flag

Sau khi license hợp lệ, chương trình tiếp tục giải mã vùng dữ liệu chứa flag.

Kết quả:

```
NNS{7h3_p47h_w4s_h1dd3n_bu7_s7r4c3_s4w_7h3_0p3n}
```

---

## 8. Final Flag

```
NNS{7h3_p47h_w4s_h1dd3n_bu7_s7r4c3_s4w_7h3_0p3n}
```

---

## 9. Lessons Learned

- Phân biệt library call và system call.
- Sử dụng `strace` để quan sát hành vi runtime.
- Hiểu syscall `openat` trong Linux.
- Reverse engineering dữ liệu được tạo động.
- Không phụ thuộc hoàn toàn vào `strings` khi phân tích binary.

**Key takeaway:** Thông tin có thể bị ẩn trong binary nhưng vẫn phải xuất hiện khi chương trình thực thi. Theo dõi syscall là cách hiệu quả để tìm các dữ liệu runtime bị che giấu.
