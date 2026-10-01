# Onyx Locker — H7CTF Write-up

- **Độ khó:** Easy
- **Thể loại:** DockerMobile
- **Điểm:** 25
- **Flag:** `H7CTF{9e8fa1e8-eb88-4fbd-9f42-44619b7a2e85}`

## 1. Mô tả và hướng tiếp cận

Đề bài nói vault chỉ lưu bí mật trên điện thoại và mã khôi phục đã được “niêm phong”. Ta cần kiểm tra hai phần: ứng dụng Android trao đổi dữ liệu gì với máy chủ, và bản lưu cục bộ `vault.enc` được bảo vệ bằng khóa nào.

## 2. Phân tích ứng dụng

Qua phân tích APK, luồng đồng bộ vault được xác định như sau:

1. App gửi `POST /api/v1/auth/device` cùng một `device_id` để nhận token.
2. App dùng token gọi `GET /api/v1/vault/sync`.
3. Phản hồi đồng bộ chứa các bản ghi có trường `secret`. App chỉ che giá trị này trên giao diện.
4. App còn lưu một bản `vault.enc` được mã hóa AES bằng khóa cố định nằm trong APK.

Như vậy, việc che bí mật khi hiển thị không làm mất trường `secret` trong dữ liệu trả về. Khóa nằm trong APK cũng cho phép giải mã bản lưu nếu có được tệp `vault.enc`.

## 3. Khai thác

Dùng script `solve_onyx.py` (hoặc bản đã đổi tên thành `sol.py`) trên máy truy cập được host thử thách:

```bash
python3 sol.py
```

Script thực hiện luồng xác thực thiết bị, đồng bộ vault và in các mục nhận được. Nếu đã trích xuất bản lưu trên thiết bị, có thể dùng nhánh giải mã cục bộ:

```bash
python3 solve_onyx.py --vault vault.enc
```

Lệnh thứ hai là phương án phân tích bản lưu; flag dưới đây được xác nhận từ đầu ra chạy `sol.py` với luồng đồng bộ.

## 4. Kết quả thực tế

Đầu ra có mục **Onyx account recovery code**:

```json
{
  "label": "Onyx account recovery code",
  "secret": "H7CTF{9e8fa1e8-eb88-4fbd-9f42-44619b7a2e85}",
  "username": ""
}
```

Script cũng in trực tiếp:

```text
Flag: H7CTF{9e8fa1e8-eb88-4fbd-9f42-44619b7a2e85}
```

## 5. Nguyên nhân lỗ hổng

Ứng dụng nhận giá trị `secret` từ API rồi chỉ ẩn nó ở tầng giao diện. Ngoài ra, khóa AES cố định được nhúng trong APK khiến bản mã cục bộ có thể bị giải mã bởi người phân tích ứng dụng. Cả hai đường đều không dựa vào bí mật chỉ chủ vault mới biết.

## Flag

```text
H7CTF{9e8fa1e8-eb88-4fbd-9f42-44619b7a2e85}
```

> Ghi chú: Write-up này dựa trên luồng phân tích và đầu ra thực tế được cung cấp; không gán giá trị `device_id`, token, khóa AES hay chế độ mã hóa cụ thể khi chưa có mã script/APK để đối chiếu.
