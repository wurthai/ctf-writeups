# NNS CTF — Reverse Engineering Write-up

**Challenge:** Flag Pointer Register
**Category:** Reverse Engineering
**Difficulty:** Beginner

---

## 1. Mô tả thử thách

Challenge cung cấp một file thực thi Windows x64 (`.exe`). Chương trình giải mã flag thành công nhưng lại in ra một thông báo sai.

**Gợi ý:**
- Theo dõi các lời gọi hàm cuối cùng.
- Kiểm tra giá trị trả về trong thanh ghi `RAX`.
- Kiểm tra cách chuẩn bị các thanh ghi `RCX`, `RDX`, `R8`, `R9` trước khi gọi `WriteFile`.
- Sửa pointer đúng vào thanh ghi chứa buffer của `WriteFile`.

**Mục tiêu:** tìm và sửa con trỏ buffer bị đặt sai.

---

## 2. Kiến thức cần biết

### Windows x64 Calling Convention

Tham số của hàm được truyền qua các thanh ghi:

| Thanh ghi | Vai trò       |
|-----------|---------------|
| `RCX`     | Argument 1    |
| `RDX`     | Argument 2    |
| `R8`      | Argument 3    |
| `R9`      | Argument 4    |

### Prototype của `WriteFile`

```c
BOOL WriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytes,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);
```

Trong đó:
- `RCX` chứa handle file.
- `RDX` chứa địa chỉ buffer cần ghi ra màn hình.
- `R8` chứa số byte cần ghi.
- `R9` chứa địa chỉ biến nhận số byte đã ghi.

Do đó **buffer in ra phải nằm trong `RDX`**.

---

## 3. Phân tích chương trình

Mở file bằng x64dbg hoặc IDA, theo dõi hàm decode flag.

Sau khi giải mã, hàm trả về địa chỉ của flag thông qua thanh ghi `RAX`:

```asm
CALL decode
```

Sau khi return:

```
RAX = địa chỉ vùng nhớ chứa flag
```

Điều này chứng minh quá trình giải mã hoàn toàn chính xác.

---

## 4. Tìm lỗi

Tiếp tục trace tới lời gọi `WriteFile`. Trước khi gọi:

```
RAX = địa chỉ flag thật
RDX = một vùng nhớ khác chứa thông báo lỗi
```

Ví dụ:

```
RAX -> Flag đã decode
RDX -> Wrong buffer
```

Do `WriteFile` sử dụng `RDX` làm buffer nên chương trình in ra nội dung sai.

---

## 5. Cách sửa trong debugger

Đặt breakpoint tại lệnh gọi `WriteFile`. Kiểm tra:

```
RAX = pointer tới flag
RDX = pointer sai
```

Sửa giá trị:

```
RDX = RAX
```

**Trong x64dbg:**
1. Break tại `WriteFile` call.
2. Modify `RDX`.
3. Nhập địa chỉ giống `RAX`.
4. Continue chương trình.

Hoặc patch tạm:

```asm
mov rdx, rax
```

---

## 6. Kết quả

Sau khi sửa pointer, `WriteFile` nhận đúng buffer chứa flag.

**Flag:**

```
NNS{r4x_h4d_7h3_fl4g_bu7_rdx_p01n73d_70_7h3_wr0ng_buff3r}
```

---

## 7. Tổng kết kiến thức

Challenge giúp luyện tập:
- Windows x64 calling convention.
- Cách truyền tham số bằng register.
- Theo dõi return value trong `RAX`.
- Debug chương trình x64 bằng x64dbg.
- Phân biệt địa chỉ dữ liệu thật và pointer bị sai.

**Điểm quan trọng:** Decoder không bị lỗi. Flag đã tồn tại trong bộ nhớ. Lỗi duy nhất là pointer buffer bị đặt sai trước khi gọi `WriteFile`.
