# No Strings Attached — Reverse Engineering Write-up

## Thông tin challenge

| | |
|---|---|
| **Challenge** | No Strings Attached |
| **Category**  | Reverse Engineering (beginner) |
| **Author**    | hoover |

**Mục tiêu:** Tìm passphrase (flag) mà chương trình sử dụng để kiểm tra input của người chơi.

---

## Phân tích ban đầu

Challenge cung cấp một file ELF x86-64. Khi chạy chương trình:

```bash
./no-strings-attached
```

Chương trình yêu cầu nhập:

```
guess:
```

Dùng `strings` để tìm flag:

```bash
strings no-strings-attached
```

Kết quả chỉ thu được:

```
guess:
correct
rejected
```

Không có flag trong binary. Điều này cho thấy passphrase được tạo ra trong lúc chạy.

---

## Ý tưởng khai thác

Đề bài gợi ý sử dụng library call tracer như `ltrace`.

Chương trình sau khi xây dựng passphrase trong bộ nhớ sẽ truyền chuỗi này vào hàm của thư viện C để so sánh với input. Hàm cần quan tâm là `strcmp()`.

---

## Dùng ltrace

Chạy:

```bash
ltrace ./no-strings-attached
```

Nhập một chuỗi bất kỳ:

```
aaaa
```

Ta quan sát được lời gọi:

```
strcmp("aaaa", "passphrase_thật")
```

`ltrace` hiển thị trực tiếp các tham số truyền vào `strcmp`, trong đó có chuỗi passphrase mà chương trình vừa tạo ra trong bộ nhớ.

---

## Kết quả

Passphrase thu được:

```
NNS{n0_str1ngs_1n_7h3_b1n4ry_bu7_ltr4c3_s4w_7h3_c0mp4r3}
```

Đây chính là flag của challenge.

---

## Giải thích

Challenge có tên *No Strings Attached* vì flag không tồn tại dưới dạng chuỗi rõ ràng trong file ELF. Nếu chạy `strings` sẽ không thấy gì quan trọng.

Tuy nhiên khi chương trình chạy:
1. Binary giải mã/xây dựng passphrase trong RAM.
2. Passphrase được đưa vào `strcmp()`.
3. `ltrace` theo dõi lời gọi thư viện và in ra các tham số.
4. Ta đọc được flag từ đối số của `strcmp()`.

---

## Kết luận

Kỹ thuật chính:
- `strings`: kiểm tra dữ liệu plaintext trong binary.
- `ltrace`: theo dõi các lời gọi thư viện.
- `strcmp` tracing: lấy secret sau khi chương trình giải mã runtime.

Đây là một bài reverse engineering nhập môn giúp làm quen với việc phân tích hành vi của chương trình thay vì chỉ tìm chuỗi trong file.
