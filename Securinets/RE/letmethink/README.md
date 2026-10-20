# letmethink — Securinets Reverse Engineering

Flag đã kiểm chứng:

```text
Securinets{5baf04ea71f2fcd7392f5598cd59d67af1152a62fb08}
```

## 1. Chạy lại phần khôi phục flag

Cần Python 3, không cần cài thư viện ngoài. Giải nén bộ lời giải, chuyển vào thư mục chứa các script rồi chạy:

```bash
python3 recover.py
```

`bytecode.bin` là bytecode thực trích từ chương trình sau giải mã. `vm.py` mô phỏng những opcode mà đường kiểm tra sử dụng. `recover.py` dò từng ký tự, sau đó chạy lại toàn bộ bytecode với flag tìm được. Bộ mô phỏng này dành cho bytecode của bài; không phải bộ thực thi đầy đủ mọi opcode của máy ảo.

## 2. Lớp ELF bên ngoài

File gốc là ELF x86-64 PIE, stripped, 25.185.512 byte. Trong khi đó các section của loader chỉ kết thúc tại offset `0x2058` (8.280). Phần còn lại là payload mã hóa được nối sau bảng section header.

Hàm tại VA `0x1cf0` tính điểm kết thúc này từ ELF header:

```python
payload_offset = e_shoff + e_shentsize * e_shnum
```

Hàm `0x1e40` có hai vòng đặc trưng của RC4: KSA hoán vị 256 byte theo khóa, rồi PRGA XOR keystream vào payload. Các lệnh SIMD nạp bảng S trông rời rạc nhưng ghép đúng thứ tự sẽ cho `0, 1, ..., 255`.

Khóa được lấy từ biến môi trường `TRUSTISKEY`; nếu chưa có, chương trình gọi `getpass` với lời nhắc `type 'letmethink' : `. Dùng khóa `letmethink` giải mã thành một ELF khác, dài 25.177.232 byte. Loader ghi ELF vào memfd rồi chạy qua `execveat`; các số syscall được XOR với `0xdeadc0de`.

`unpack.py` thực hiện việc giải mã tĩnh, không chạy file gốc:

```bash
unzip -P 6fa56075bb63c21be94f60445c3cb575a36048ec808e3ec77bb49dd8329fc1a7 'letmethink(1).zip'
python3 unpack.py ./letmethink --compat
```

## 3. ELF Go bên trong và điểm trích bytecode

Payload là chương trình Go có làm rối tên và chuỗi. `.gopclntab` vẫn giúp xác định ranh giới các hàm. Cần chú ý entry offset trong bảng hàm được cộng với địa chỉ bắt đầu mã Go `0x26a600`, không phải đầu section `.text` (`0x26a4c0`).

Các vị trí hữu ích trong ELF đã giải mã:

| VA | Vai trò |
|---|---|
| `0xf705e0` | Hàm thiết lập và chạy máy ảo |
| `0xf7d3e0` | Kiểm tra môi trường/debug |
| `0xf70440` | Push giá trị 32 bit |
| `0xf704e0` | Pop giá trị 32 bit |
| `0xf70c78` | Nạp con trỏ VM trước vòng dispatch |
| `0xf70c80` | Đầu vòng dispatch |

Bytecode đi qua bước giải mã AES-CBC rồi một lớp XOR biến đổi theo vị trí trước khi được đưa vào VM. Có thể tránh tái tạo toàn bộ chuỗi giải mã bằng cách trích dữ liệu ngay trước vòng dispatch.

Cấu trúc VM có stack 32.768 số nguyên 32 bit, chỉ số đỉnh stack tại `+0x20000`, PC tại `+0x20008`, con trỏ bytecode tại `+0x20010`, độ dài tại `+0x20018`. Giá trị stack được XOR với một khóa byte tại `+0x20029`; push/pop loại bỏ lớp biểu diễn này, nên bộ mô phỏng giữ giá trị logic trực tiếp.

`dump.c` gắn hook vào bản phân tích để ghi bytecode rồi kết thúc tiến trình. Chỉ chạy các lệnh sau trong môi trường Linux phân tích CTF:

```bash
gcc -O0 -shared -fPIC -o analysis/dump.so dump.c
timeout 15 env LD_PRELOAD="$PWD/analysis/dump.so" analysis/debug </dev/null
cmp bytecode.bin analysis/bytecode.bin
```

`--compat` tạo `analysis/runnable` với điều chỉnh metadata phiên bản `sinh/cosh` từ GLIBC_2.44 sang GLIBC_2.2.5 để chạy trên môi trường phân tích GLIBC 2.39. Nó cũng tạo `analysis/debug`, bản riêng có hàm kiểm tra debug trả về false để dùng hook. File gốc và `analysis/layer1` được giữ nguyên. Không cần những bước chạy native này để chạy `recover.py` với bytecode đính kèm.

## 4. Khôi phục quy tắc kiểm tra

Những opcode chính dùng trong lời giải:

| Opcode | Ý nghĩa logic |
|---|---|
| `a7 imm32` | Push hằng 32 bit little endian |
| `e1` | Đọc ký tự input; hết input trả 0 |
| `7a` / `3e` | Duplicate / pop |
| `9a` | Pop b, a; push tổng input[a:b] |
| `94` / `e3` | XOR / AND |
| `b3` | Dịch trái 32 bit |
| `f2` | Cộng 32 bit |
| `6d` | So sánh bằng |
| `d7` | SHA-256 của số vừa pop, biểu diễn 4 byte little endian; push 32 byte digest theo thứ tự ngược |
| `4e` | Pop n rồi cộng n giá trị trên stack |
| `58 target` / `a2 target` | Nhảy khi giá trị pop bằng 0 / khác 0 |
| `2f` / `00` | In ký tự / dừng |

Đầu bytecode in `Enter flag: `, đọc đến byte 0 (tối đa 100 lượt) và yêu cầu độ dài 56. Tiếp theo là 56 khối so sánh, cộng số điều kiện đúng, rồi kiểm tra tổng bằng 56. Thành công in `Correct!`, thất bại in `Wrong!`.

Các khối dùng một giá trị chung được tính từ 11 ký tự đầu. Trong bài này tiền tố `Securinets{` dài đúng 11 ký tự. Một biểu thức chung xuất hiện nhiều lần có dạng:

```python
m = 0
for ch in input_bytes[:11]:
    m = ((m << 1) ^ ch) & 0xffffffff
m = ((m << 3) ^ 103) & 0xffffffff
```

Khi giữ cố định tiền tố, mỗi khối còn lại chỉ phụ thuộc một ký tự cần tìm cùng các hằng số và phép hash trong khối. Vì thế có thể thử 95 ký tự ASCII in được cho từng vị trí; không cần brute force toàn flag. Khối đầu bắt đầu tại `0x82f`; phép so sánh đầu tại `0xc0f`. Sau mỗi phép so sánh là lệnh cộng kết quả vào bộ đếm. Script tách các khối tại những điểm này, thử từng ký tự rồi chạy lại cả chương trình để xác nhận. Việc giả định tiền tố chỉ là bước giảm không gian tìm kiếm; kết quả cuối được xác nhận bằng chương trình native.

## 5. Kiểm chứng

Chạy `analysis/runnable` (giữ nguyên logic kiểm tra, chỉ điều chỉnh metadata GLIBC như trên), không dùng hook và không vá hàm anti-debug:

```text
Securinets{5baf04ea71f2fcd7392f5598cd59d67af1152a62fb08}
=> Enter flag: Correct!

Securinets{6baf04ea71f2fcd7392f5598cd59d67af1152a62fb08}
=> Enter flag: Wrong!
```

Cả hai lượt thoát với mã 0, nên phải kiểm tra nội dung output thay vì chỉ nhìn exit code. Chưa có xác nhận từ hệ thống chấm điểm của cuộc thi.

SHA-256 để đối chiếu:

```text
letmethink:
aed9c42ac4fe37d579499753ea2886bdfdffe2e60b2631802518d5805593c42a

ELF Go nguyên trạng:
2e0ddba983005c9b5b60ad79ec6c5337a114acdca496258a858f9802ad640479

bytecode.bin:
2303375766520462b813dda5648e7a50589df3fd8552a747cbb28b1dc8148c6f
```
