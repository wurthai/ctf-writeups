# srev — K17 CTF

## Flag

```text
K17{00p$_nO_s1g$}
```

Chú ý: hai ký tự đầu là số `0`; trong `nO` là chữ `O` hoa; trong `s1g` là số `1`. Hai ký tự `$` là một phần của flag.

## 1. Thông tin file và hướng tiếp cận

File đính kèm là ELF 64-bit x86-64, little-endian, dynamically linked, đã stripped và không phải PIE.

SHA-256:

```text
7e9dabbfc9da355da6ea2649e834a449898daca8d911860e6de2667c3b664358
```

Các lệnh khảo sát:

```bash
file srev
readelf -S srev
objdump -T srev
strings -a srev
objdump -d -Mintel srev
```

Các hàm import đáng chú ý gồm `sigaction`, `raise`, `memcpy`, `putc`, `fwrite`. Chương trình không đọc flag từ người dùng; nó tự sinh ứng viên, kiểm tra rồi in kết quả.

Các chuỗi `halt: empty stack`, `halt: depth=%zu` và `r%u=%#lx` gợi ý một máy ảo có stack và thanh ghi. Chuỗi `K17{` nằm ở địa chỉ ảo `0x41538e`.

## 2. Lớp đánh lạc hướng: máy ảo dùng rt_sigreturn

Hàm main tại `0x401150` thiết lập handler cho signal 10 rồi gọi `raise(10)`. Handler tại `0x4013b0` sao chép `0x3c8` byte trạng thái được truyền vào.

Dispatcher tại `0x401480` lấy một bản ghi lệnh, dựng trạng thái thực thi rồi chạy:

```asm
mov rsp, rcx
mov rax, 0xf
syscall
```

Đây là `rt_sigreturn`: trạng thái được dựng sẵn quyết định thanh ghi và địa chỉ thực thi tiếp theo. Trường ở offset `0xa8` của bản ghi chứa opcode, được dispatcher thay bằng địa chỉ handler tương ứng trước khi chuyển điều khiển. Trường ở offset `0x90` chứa argument của lệnh.

Vì vậy, có thể bỏ qua cách chuyển điều khiển phức tạp của hệ điều hành và mô phỏng trực tiếp ý nghĩa của lệnh VM.

## 3. Cấu trúc dữ liệu VM

Các giá trị dưới đây là **file offset** của đúng binary đính kèm:

| Thành phần | Offset | Ý nghĩa |
|---|---:|---|
| Bảng ánh xạ thanh ghi | `0x2060` | 16 số nguyên 64-bit |
| Header `SREV` | `0x20e0` | Version `0x100`, 25 template, 291 lệnh |
| Bảng template | `0x20f8` | 25 bản ghi, mỗi bản ghi `0xfc` byte |
| Bảng lệnh | `0x3994` | 291 bản ghi, mỗi bản ghi `0xf8` byte |

Mỗi template có một trường 4 byte trước phần context. Thanh ghi `r1..r13` nằm tại offset `0x28..0x88` trong context, `r14` tại `0x98`, `r15` tại `0xa8`.

Template 0 khởi tạo `r1..r12` bằng `0x20`, tức 12 dấu cách. `r15` được dùng làm thông tin chuyển điều khiển; các template còn lại hỗ trợ nhánh thất bại và vòng lặp.

Các opcode:

| Opcode | Ý nghĩa |
|---:|---|
| 1 | Trả kết quả được chọn về frame trước rồi pop |
| 2 | Push một template, có thể kèm điều kiện |
| 3 | Sao chép một frame trong stack, có thể kèm điều kiện |
| 4 | Bỏ một số frame khỏi stack |
| 5 | ADD |
| 6 | SUB |
| 7 | XOR |
| 8 | ROR 64-bit |
| 9 | HALT và xuất kết quả |

Với opcode số học, cách giải mã argument là:

```python
dst = argument & 0xf
is_immediate = bool(argument & 0x10)
operand = argument >> 8 if is_immediate else registers[(argument >> 8) & 0xf]
```

Mọi phép toán được giới hạn trong 64 bit.

## 4. Vì sao chương trình chạy quá lâu?

Luồng chính của VM:

1. PC 0 tạo trạng thái ứng viên ban đầu.
2. PC 1 sao chép ứng viên để kiểm tra, giữ lại bản chưa biến đổi.
3. PC 2–237 biến đổi 12 thanh ghi bằng XOR, ADD và SUB.
4. PC 238–249 kiểm tra lần lượt `r1..r12`; thanh ghi nào khác 0 thì đi vào nhánh thất bại.
5. Nếu tất cả bằng 0, PC 250 bỏ bản đã biến đổi; PC 251 in flag từ ứng viên được giữ lại.
6. Nếu sai, PC 252–290 tăng ứng viên theo thứ tự, bắt đầu từ ký tự cuối, trong miền ASCII `0x20..0x7e`, rồi kiểm tra tiếp.

Không gian ứng viên là:

```text
95^12 = 540360087662636962890625
```

Đây là lý do gợi ý “Time Limit Exceeded” xuất hiện trong đề. Viết emulator rồi vẫn vét cạn từng ứng viên sẽ không giải quyết được vấn đề chính.

## 5. Đảo ngược toàn bộ phép kiểm tra

PC 2–13 XOR từng thanh ghi với một hằng số. Các đoạn tiếp theo trộn thanh ghi bằng cộng hằng số, cộng thanh ghi và các cụm XOR đổi chỗ. Ví dụ:

```text
r1 ^= r4
r4 ^= r1
r1 ^= r4
```

Ba phép XOR này hoán đổi `r1` và `r4`.

Cuối cùng PC 226–237 trừ 12 hằng số đích. Điều kiện thành công là toàn bộ kết quả bằng 0, nên ta biết chính xác trạng thái cuối và có thể chạy ngược từ đó.

| Phép thuận | Phép ngược |
|---|---|
| `x += y` | `x -= y` |
| `x -= y` | `x += y` |
| `x ^= y` | `x ^= y` |
| `x = ror64(x, n)` | `x = rol64(x, n)` |

Đoạn biến đổi thực tế của file dùng ADD, SUB và XOR. Solver cũng hỗ trợ ROR theo tập lệnh VM.

Phải xử lý các lệnh **theo thứ tự ngược** để khôi phục đúng giá trị thanh ghi nguồn ở từng bước. Trong đoạn đang xét, toán hạng nguồn dạng thanh ghi luôn khác thanh ghi đích, nên từng phép này đảo ngược được.

Thuật toán rút gọn:

```python
r = [0] * 16
mask = (1 << 64) - 1

for opcode, argument in reversed(program[2:238]):
    dst = argument & 15
    src = argument >> 8 if argument & 16 else r[(argument >> 8) & 15]

    if opcode == 5:
        r[dst] = (r[dst] - src) & mask
    elif opcode == 6:
        r[dst] = (r[dst] + src) & mask
    elif opcode == 7:
        r[dst] ^= src
```

Kết quả `r1..r12`:

```text
[48, 48, 112, 36, 95, 110, 79, 95, 115, 49, 103, 36]
```

Đổi sang ASCII:

```text
00p$_nO_s1g$
```

Thay vì duyệt một không gian khổng lồ, chỉ cần đảo ngược 236 lệnh số học.

## 6. Kiểm chứng

Đã thực hiện hai kiểm tra:

**Kiểm tra thuận:** đưa chuỗi khôi phục vào PC 2–237. Kết quả cả 12 thanh ghi đều bằng 0, đúng với điều kiện thành công.

**Chạy binary:** tạo bản sao tạm thời của file, thay 12 giá trị khởi tạo của template 0 từ dấu cách thành chuỗi vừa tìm được. Giữ nguyên dispatcher, toàn bộ phép biến đổi, nhánh kiểm tra và hàm in flag.

Kết quả thực tế:

```text
returncode: 0
stdout: K17{00p$_nO_s1g$}
stderr: (rỗng)
```

Đây là kiểm chứng bằng logic kiểm tra của binary, không phải sửa nhánh để ép chương trình in một chuỗi tùy ý. File đính kèm gốc không bị thay đổi.

## 7. Chạy solver

Đặt `solve_srev.py` và `srev` trong cùng thư mục:

```bash
python3 solve_srev.py ./srev
```

Không cần Sage, pwntools hoặc thư viện ngoài. Solver đọc file như dữ liệu và chạy được bằng Python 3.

Trên Linux x86-64, có thể kiểm chứng thêm bằng bản sao thực thi:

```bash
python3 solve_srev.py ./srev --verify-native
```

Kết quả:

```text
[+] Reversed 236 arithmetic instructions
[+] Forward check: all 12 result registers are zero
[+] Native copy: exit 0, exact flag output
K17{00p$_nO_s1g$}
```

Tùy chọn `--verify-native` tạo và chạy một bản sao tạm thời rồi xóa nó; không sửa file `srev` của bạn.
