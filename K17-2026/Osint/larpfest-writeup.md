# larpfest — Write-up CTF OSINT

## 1. Thông tin thử thách

- **Tên:** larpfest
- **Độ khó:** Easy
- **Chủ đề:** OSINT, Git, GitHub Events, khôi phục commit không còn trên nhánh.
- **Repository:** [larp-larp-larp/larp](https://github.com/larp-larp-larp/larp)

Đề bài cho biết flag đang hoặc từng nằm trong repository. Cụm “is (or was...)” gợi ý cần kiểm tra dữ liệu trong quá khứ, thay vì chỉ đọc các file hiện tại.

## 2. Flag

```text
K17{l00k_im_a_1337_h4x0r}
```

Flag đã được đọc trực tiếp từ file `.env` trong commit:

```text
2ff1293a0da908202dc16628e5c1fa68c05294ec
```

Kết quả được xác minh bằng cả GitHub API và lệnh `git show`. Write-up này không ghi nhận việc nộp flag lên hệ thống chấm.

## 3. Kiểm tra repository và lịch sử hiện tại

Clone repository đầy đủ, không dùng `--depth 1`:

```bash
git clone https://github.com/larp-larp-larp/larp.git
cd larp
git log --all --oneline --decorate --stat
```

Tại thời điểm kiểm tra, lịch sử nhánh `main` có ba commit:

```text
4df7ab7 the larp is unlimited
afb99a4 oops
795d5d2 coding
```

Các file gồm `code.cpp`, `wishlist.txt`, `my_os.png` và `.env`.

Đọc thay đổi của các file văn bản:

```bash
git log --all -p -- .env code.cpp wishlist.txt
```

Commit `afb99a4` có thông điệp `oops`, thêm file `.env` với nội dung:

```env
OPENAI_API_KEY="please ignore"
```

Đây là dấu hiệu đáng chú ý: tên file thường được dùng để chứa biến môi trường, nhưng giá trị hiện tại chỉ là lời nhắn “please ignore”. Tuy nhiên, riêng chi tiết này chưa đủ chứng minh flag từng nằm ở đây.

Kiểm tra các tham chiếu từ xa và object không còn được tham chiếu trong bản clone:

```bash
git ls-remote origin
git fsck --full --no-reflogs --unreachable
```

Kết quả chỉ cho thấy nhánh `main`; `git fsck` không tìm thấy object thất lạc trong bản clone. Vì vậy, cần tìm dấu vết bên ngoài lịch sử Git đã tải về.

## 4. Tìm commit bị loại khỏi lịch sử qua GitHub Events

GitHub cung cấp API liệt kê hoạt động công khai của tài khoản:

[GitHub Events của larp-larp-larp](https://api.github.com/users/larp-larp-larp/events/public?per_page=100)

Có thể dùng `curl` và `jq` để lọc các lần push vào đúng repository:

```bash
curl -fsSL 'https://api.github.com/users/larp-larp-larp/events/public?per_page=100' |
  jq '.[] | select(.type == "PushEvent" and .repo.name == "larp-larp-larp/larp") | {created_at, before: .payload.before, head: .payload.head}'
```

Một sự kiện quan trọng trả về các trường sau:

```json
{
  "created_at": "2026-09-06T15:41:08Z",
  "before": "2ff1293a0da908202dc16628e5c1fa68c05294ec",
  "head": "afb99a47719c4fdf23beeb2a446cde0126fc3cf1"
}
```

Ý nghĩa:

- `before`: commit ở đầu nhánh trước lần push.
- `head`: commit ở đầu nhánh sau lần push.
- Commit `2ff1293a...` xuất hiện trong sự kiện nhưng không nằm trong lịch sử `main` vừa clone.

Một sự kiện trước đó cũng ghi nhận nhánh từng chuyển từ `795d5d2...` sang `2ff1293a...`. Các dấu vết này cho thấy lịch sử đã được viết lại; không thể xác định chính xác lệnh người tạo repo đã dùng chỉ từ những trường trên.

| Thời điểm UTC | Commit trước push | Commit sau push |
| --- | --- | --- |
| 2026-09-06 15:37:13 | `795d5d2...` | `2ff1293a...` |
| 2026-09-06 15:41:08 | `2ff1293a...` | `afb99a4...` |
| 2026-09-06 15:53:50 | `afb99a4...` | `4df7ab7...` |

## 5. Đọc commit cũ và lấy flag

### Cách 1: Mở commit trên GitHub

Truy cập [commit 2ff1293a0da908202dc16628e5c1fa68c05294ec](https://github.com/larp-larp-larp/larp/commit/2ff1293a0da908202dc16628e5c1fa68c05294ec).

Thông điệp commit:

```text
chat said i needed this file
```

Commit thêm file `.env` với nội dung:

```env
OPENAI_API_KEY="K17{l00k_im_a_1337_h4x0r}"
```

### Cách 2: Dùng GitHub API

```bash
curl -fsSL 'https://api.github.com/repos/larp-larp-larp/larp/commits/2ff1293a0da908202dc16628e5c1fa68c05294ec' |
  jq -r '.files[] | select(.filename == ".env") | .patch'
```

Kết quả:

```diff
@@ -0,0 +1 @@
+OPENAI_API_KEY="K17{l00k_im_a_1337_h4x0r}"
```

### Cách 3: Fetch commit theo SHA

Trong thư mục repository đã clone:

```bash
git fetch origin 2ff1293a0da908202dc16628e5c1fa68c05294ec
git show 2ff1293a0da908202dc16628e5c1fa68c05294ec:.env
```

Kết quả đã kiểm chứng:

```text
OPENAI_API_KEY="K17{l00k_im_a_1337_h4x0r}"
```

Cú pháp `git show <commit>:<file>` đọc file tại đúng phiên bản đó, không cần checkout hay thay đổi các file đang làm việc.

## 6. Vì sao chỉ dùng git log không thấy flag?

`git log --all` duyệt lịch sử từ các tham chiếu mà bản clone biết. Nó không liệt kê mọi commit từng tồn tại trên máy chủ GitHub.

Sau khi lịch sử được viết lại, commit cũ có thể không còn là tổ tiên của bất kỳ nhánh hoặc tag được tải về nào. Một bản clone mới vì thế có thể không chứa object đó, nên `git fsck` cũng không thể tìm ra nó ở máy cục bộ.

Trong bài này, GitHub Events làm lộ SHA của commit cũ. Khi biết SHA, ta vẫn truy cập được nội dung qua GitHub API và fetch trực tiếp bằng Git tại thời điểm giải.

Khả năng truy cập commit cũ và sự hiện diện của sự kiện có thể thay đổi theo thời gian; cách khôi phục này không phải lúc nào cũng còn hoạt động.

## 7. Vai trò của ảnh my_os.png

Repository có ảnh chụp màn hình Kali Linux tên `my_os.png`. Trong quá trình kiểm tra, ảnh không cung cấp manh mối cần thiết cho lời giải; việc đọc cấu trúc PNG cũng không phát hiện dữ liệu nối sau chunk `IEND`.

Flag thực tế đã được xác minh trong `.env` của commit cũ. Vì vậy, không cần giải steganography để hoàn thành bài này. Điều đó không đồng nghĩa đã chứng minh ảnh hoàn toàn không có dữ liệu ẩn.

## 8. Các lệnh ngắn gọn để làm lại

Nếu chưa clone repository:

```bash
git clone https://github.com/larp-larp-larp/larp.git
cd larp
```

Nếu đã có bản clone, chỉ cần vào thư mục đó rồi chạy:

```bash
git log --all --oneline

curl -fsSL 'https://api.github.com/users/larp-larp-larp/events/public?per_page=100' |
  jq '.[] | select(.type == "PushEvent" and .repo.name == "larp-larp-larp/larp") | .payload'

git fetch origin 2ff1293a0da908202dc16628e5c1fa68c05294ec
git show 2ff1293a0da908202dc16628e5c1fa68c05294ec:.env
```

## 9. Bài học rút ra

- Khi đề nhấn mạnh dữ liệu “từng tồn tại”, hãy kiểm tra lịch sử và nhật ký hoạt động.
- Thông điệp như `oops` là manh mối để điều tra, chưa phải bằng chứng kết luận.
- Viết lại lịch sử nhánh không bảo đảm nội dung cũ lập tức biến mất khỏi GitHub.
- SHA commit có thể xuất hiện trong GitHub Events ngay cả khi commit không còn trên nhánh hiện tại.
- Nếu bí mật thật từng bị công khai, cần thu hồi hoặc thay khóa; chỉ sửa file hoặc viết lại lịch sử là chưa đủ.

## 10. Nguồn bằng chứng

- [Repository gốc](https://github.com/larp-larp-larp/larp)
- [Nhật ký hoạt động công khai của tài khoản](https://api.github.com/users/larp-larp-larp/events/public?per_page=100)
- [Commit chứa flag](https://github.com/larp-larp-larp/larp/commit/2ff1293a0da908202dc16628e5c1fa68c05294ec)
- [API của commit chứa flag](https://api.github.com/repos/larp-larp-larp/larp/commits/2ff1293a0da908202dc16628e5c1fa68c05294ec)
- [File .env tại commit chứa flag](https://github.com/larp-larp-larp/larp/blob/2ff1293a0da908202dc16628e5c1fa68c05294ec/.env)
