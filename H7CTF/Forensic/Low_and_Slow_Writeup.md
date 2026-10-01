# H7CTF 2026 – Low and Slow

- **Category:** Forensics
- **Difficulty:** Medium
- **Points:** 63
- **Artifact:** `capture.pcap`
- **Technique:** DNS covert channel / DNS exfiltration / Base32 chunking
- **Flag:** `H7CTF{6787b86cc777f426b9c0}`

---

## 1. Challenge Description

> Six weeks, not one alert, a clean bill of health on every dashboard that mattered. Then a partner asks why your unreleased designs are making the rounds.
>
> Something in here has been talking to the outside on a very patient schedule.

Tên bài **Low and Slow** cùng mô tả cho thấy dữ liệu có thể không bị lấy đi bằng một kết nối lớn hoặc một đợt truyền dữ liệu rõ ràng. Thay vào đó, attacker có khả năng chia nhỏ dữ liệu và truyền ra ngoài theo từng phần nhỏ, với tần suất thấp, xen lẫn traffic hợp lệ.

Đây là kiểu hành vi thường gặp trong các **covert channel**, đặc biệt là **DNS exfiltration**, vì DNS thường được cho phép đi qua firewall và lượng dữ liệu nhỏ trong từng query dễ bị bỏ qua nếu chỉ giám sát lưu lượng tổng thể.

---

## 2. Mục tiêu phân tích

Ta cần trả lời các câu hỏi sau:

1. PCAP chứa những protocol nào?
2. Có host/domain nào xuất hiện bất thường không?
3. Có traffic lặp lại theo chu kỳ hoặc có pattern mã hóa không?
4. Dữ liệu bị giấu ở đâu trong packet?
5. Có thể tái dựng payload để lấy flag hay không?

---

## 3. Triage ban đầu

Mở file bằng Wireshark:

```bash
wireshark capture.pcap
```

Hoặc dùng `tshark` để xem thống kê:

```bash
tshark -r capture.pcap -q -z io,phs
```

PCAP có tổng cộng khoảng:

```text
1260 packets
Capture duration: ~148.3 seconds
TCP packets: 1080
UDP packets: 180
```

Phần lớn traffic là TCP. Tuy nhiên, vì mô tả nhấn mạnh một tác nhân “talking to the outside” theo lịch rất chậm, DNS là một protocol đáng kiểm tra trước.

Filter trong Wireshark:

```text
dns
```

Hoặc command line:

```bash
tshark -r capture.pcap -Y dns
```

---

## 4. Liệt kê DNS query

Có thể trích riêng tên miền được query bằng:

```bash
tshark -r capture.pcap \
  -Y 'dns.flags.response == 0 && dns.qry.name' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e dns.qry.name
```

Hoặc chỉ thống kê query name:

```bash
tshark -r capture.pcap \
  -Y 'dns.flags.response == 0 && dns.qry.name' \
  -T fields -e dns.qry.name | sort | uniq -c | sort -nr
```

Các DNS query bình thường trong capture gồm những domain như:

```text
updates.ubuntu.com
api.weather.example
pool.ntp.org
mirror.lab.local
logging.googleapis.com
grafana.internal.lab
cdn.jsdelivr.net
```

Nhưng có ba tên miền rất đáng ngờ:

```text
00ja3ugvcgpm3doobx.sync.cdn-telemetry-lab.net
01mi4dmy3dg43tozru.sync.cdn-telemetry-lab.net
02gi3geoldgb6q.sync.cdn-telemetry-lab.net
```

Mỗi query xuất hiện hai lần, tổng cộng 6 request đáng ngờ.

---

## 5. Tại sao các DNS query này đáng ngờ?

### 5.1. Subdomain có entropy cao

Phần đầu của domain:

```text
00ja3ugvcgpm3doobx
01mi4dmy3dg43tozru
02gi3geoldgb6q
```

không giống hostname thông thường.

Chúng trông giống dữ liệu đã được encode.

### 5.2. Có sequence number

Hai ký tự đầu lần lượt là:

```text
00
01
02
```

Đây là dấu hiệu rất mạnh cho thấy payload đã được chia thành nhiều **chunk** và đánh số thứ tự để phía nhận ghép lại.

### 5.3. Cùng một suffix

Tất cả đều nằm dưới:

```text
sync.cdn-telemetry-lab.net
```

Mẫu truyền dữ liệu có dạng:

```text
<sequence><encoded_data>.sync.cdn-telemetry-lab.net
```

Đây là một cấu trúc rất điển hình của DNS tunneling/exfiltration.

### 5.4. Query được phát thưa

Ba request đầu xuất hiện tại khoảng:

```text
05:34:51 UTC  -> chunk 00
05:34:57 UTC  -> chunk 01
05:35:05 UTC  -> chunk 02
```

Sau đó chúng được lặp lại:

```text
05:35:17 UTC  -> chunk 00
05:35:25 UTC  -> chunk 01
05:35:32 UTC  -> chunk 02
```

Khoảng cách giữa các query vào khoảng vài giây đến hơn 10 giây thay vì gửi liên tục.

Đây chính là ý nghĩa của **Low and Slow**: attacker cố tránh tạo spike lưu lượng dễ bị phát hiện.

---

## 6. Filter trực tiếp traffic đáng ngờ

Trong Wireshark:

```text
dns.qry.name contains "cdn-telemetry-lab.net"
```

Có thể chỉ lấy request, bỏ response:

```text
dns.flags.response == 0 && dns.qry.name contains "cdn-telemetry-lab.net"
```

Tương đương với `tshark`:

```bash
tshark -r capture.pcap \
  -Y 'dns.flags.response == 0 && dns.qry.name contains "cdn-telemetry-lab.net"' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name
```

Kết quả logic sẽ cho thấy:

```text
00ja3ugvcgpm3doobx.sync.cdn-telemetry-lab.net
01mi4dmy3dg43tozru.sync.cdn-telemetry-lab.net
02gi3geoldgb6q.sync.cdn-telemetry-lab.net
00ja3ugvcgpm3doobx.sync.cdn-telemetry-lab.net
01mi4dmy3dg43tozru.sync.cdn-telemetry-lab.net
02gi3geoldgb6q.sync.cdn-telemetry-lab.net
```

---

## 7. Phân tích DNS response

Các query đáng ngờ đi từ:

```text
127.0.0.1 -> 127.0.0.53:53
```

`127.0.0.53` thường là local DNS stub resolver của `systemd-resolved`.

Response có DNS flags:

```text
0x8183
```

Giải thích nhanh:

- `0x8000`: response
- `0x0100`: recursion desired
- `0x0080`: recursion available
- lower RCODE = `3`

RCODE `3` là:

```text
NXDOMAIN
```

Tức là tên miền không resolve thành công.

Điều này **không làm DNS exfiltration thất bại**. Payload đã nằm ngay trong query name và được gửi ra DNS infrastructure trước khi client nhận NXDOMAIN.

Để filter NXDOMAIN trong Wireshark:

```text
dns.flags.rcode == 3
```

Hoặc vừa NXDOMAIN vừa đúng domain:

```text
dns.flags.rcode == 3 && dns.qry.name contains "cdn-telemetry-lab.net"
```

---

## 8. Tách payload khỏi domain

Ta có:

```text
00ja3ugvcgpm3doobx.sync.cdn-telemetry-lab.net
01mi4dmy3dg43tozru.sync.cdn-telemetry-lab.net
02gi3geoldgb6q.sync.cdn-telemetry-lab.net
```

Bỏ suffix:

```text
.sync.cdn-telemetry-lab.net
```

còn lại:

```text
00ja3ugvcgpm3doobx
01mi4dmy3dg43tozru
02gi3geoldgb6q
```

Bỏ tiếp 2 ký tự sequence number:

```text
ja3ugvcgpm3doobx
mi4dmy3dg43tozru
gi3geoldgb6q
```

---

## 9. Nhận diện Base32

Các chuỗi còn lại chỉ chứa:

```text
a-z
2-7
```

Đây chính là alphabet đặc trưng của **Base32**:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
```

DNS name không phân biệt hoa/thường nên attacker có thể dùng lowercase để payload trông tự nhiên hơn.

Ta thử decode từng chunk bằng Base32.

---

## 10. Decode thủ công bằng Python

Tạo file `decode.py`:

```python
import base64

chunks = [
    "ja3ugvcgpm3doobx",
    "mi4dmy3dg43tozru",
    "gi3geoldgb6q",
]

for chunk in chunks:
    # Base32 cần chiều dài là bội số của 8.
    padding = "=" * ((8 - len(chunk) % 8) % 8)
    decoded = base64.b32decode(chunk.upper() + padding)
    print(decoded.decode())
```

Chạy:

```bash
python3 decode.py
```

Output:

```text
H7CTF{6787
b86cc777f4
26b9c0}
```

Ghép ba phần:

```text
H7CTF{6787b86cc777f426b9c0}
```

---

## 11. Flag

```text
H7CTF{6787b86cc777f426b9c0}
```

---

# 12. Tự động hóa toàn bộ quá trình

Ta có thể dùng `tshark` + Python để tự động lấy payload trực tiếp từ PCAP.

## Cách 1 – Bash + tshark

Lấy các query:

```bash
tshark -r capture.pcap \
  -Y 'dns.flags.response == 0 && dns.qry.name contains "sync.cdn-telemetry-lab.net"' \
  -T fields -e dns.qry.name
```

Lấy phần label đầu tiên:

```bash
tshark -r capture.pcap \
  -Y 'dns.flags.response == 0 && dns.qry.name contains "sync.cdn-telemetry-lab.net"' \
  -T fields -e dns.qry.name \
  | cut -d. -f1
```

Bỏ query trùng:

```bash
tshark -r capture.pcap \
  -Y 'dns.flags.response == 0 && dns.qry.name contains "sync.cdn-telemetry-lab.net"' \
  -T fields -e dns.qry.name \
  | cut -d. -f1 \
  | awk '!seen[$0]++'
```

Output:

```text
00ja3ugvcgpm3doobx
01mi4dmy3dg43tozru
02gi3geoldgb6q
```

---

## Cách 2 – Python nhận danh sách query rồi tự decode

```python
#!/usr/bin/env python3
import base64

queries = [
    "00ja3ugvcgpm3doobx.sync.cdn-telemetry-lab.net",
    "01mi4dmy3dg43tozru.sync.cdn-telemetry-lab.net",
    "02gi3geoldgb6q.sync.cdn-telemetry-lab.net",
]

chunks = {}

for query in queries:
    first_label = query.split(".")[0]

    seq = int(first_label[:2])
    encoded = first_label[2:]

    chunks[seq] = encoded

flag = b""

for seq in sorted(chunks):
    encoded = chunks[seq].upper()
    encoded += "=" * ((8 - len(encoded) % 8) % 8)
    flag += base64.b32decode(encoded)

print(flag.decode())
```

Output:

```text
H7CTF{6787b86cc777f426b9c0}
```

---

# 13. Script tự động đọc PCAP bằng tshark

Có thể viết script hoàn chỉnh để không cần copy query thủ công:

```python
#!/usr/bin/env python3

import subprocess
import base64

PCAP = "capture.pcap"
DOMAIN = "sync.cdn-telemetry-lab.net"

cmd = [
    "tshark",
    "-r", PCAP,
    "-Y", f'dns.flags.response == 0 && dns.qry.name contains "{DOMAIN}"',
    "-T", "fields",
    "-e", "dns.qry.name",
]

output = subprocess.check_output(cmd, text=True)

chunks = {}

for query in output.splitlines():
    query = query.strip()
    if not query:
        continue

    first_label = query.split(".")[0]

    sequence = int(first_label[:2])
    payload = first_label[2:]

    # Dictionary tự loại bỏ retransmission / duplicate query.
    chunks[sequence] = payload

result = b""

for sequence in sorted(chunks):
    payload = chunks[sequence].upper()
    payload += "=" * ((8 - len(payload) % 8) % 8)
    result += base64.b32decode(payload)

print(result.decode())
```

Chạy:

```bash
python3 solve.py
```

Kết quả:

```text
H7CTF{6787b86cc777f426b9c0}
```

---

# 14. One-liner để kiểm tra nhanh

Nếu đã biết ba chunk:

```bash
python3 - <<'PY'
import base64
x=['ja3ugvcgpm3doobx','mi4dmy3dg43tozru','gi3geoldgb6q']
print(''.join(base64.b32decode(s.upper()+'='*((8-len(s)%8)%8)).decode() for s in x))
PY
```

Output:

```text
H7CTF{6787b86cc777f426b9c0}
```

---

# 15. Vì sao kỹ thuật này có thể qua mặt giám sát?

Bài challenge mô phỏng một kỹ thuật exfiltration khá thực tế.

Thay vì gửi một file lớn trực tiếp ra Internet, malware có thể:

1. Đọc dữ liệu cần đánh cắp.
2. Encode dữ liệu bằng Base32/Base64/hex.
3. Chia dữ liệu thành các chunk nhỏ.
4. Đánh sequence number cho từng chunk.
5. Đặt chunk vào DNS subdomain.
6. Query domain do attacker kiểm soát.
7. Chờ một khoảng thời gian trước khi gửi chunk tiếp theo.

Ví dụ:

```text
Secret data
    |
    v
Base32 encode
    |
    v
split chunks
    |
    +--> 00AAAA.attacker.com
    +--> 01BBBB.attacker.com
    +--> 02CCCC.attacker.com
```

Authoritative DNS server của attacker có thể log toàn bộ hostname được query và tái dựng dữ liệu mà không cần DNS response chứa dữ liệu có ý nghĩa.

---

# 16. Tại sao dùng Base32 thay vì Base64?

Base64 thường chứa các ký tự:

```text
+
/
=
```

Các ký tự này không phù hợp để nhúng trực tiếp vào DNS label.

Base32 chủ yếu dùng:

```text
A-Z
2-7
```

nên rất thuận tiện cho DNS tunneling.

Trong challenge, attacker chuyển chuỗi thành lowercase:

```text
ja3ugvcgpm3doobx
```

nhưng điều này không ảnh hưởng vì DNS hostname không phân biệt hoa/thường và Python có thể uppercase lại trước khi decode.

---

# 17. Ý nghĩa của duplicate query

Capture chứa hai lượt:

```text
00 -> 01 -> 02
00 -> 01 -> 02
```

Có thể coi đây là retry/retransmission ở tầng ứng dụng để tăng khả năng payload được authoritative DNS infrastructure ghi nhận.

Khi viết solver, không nên ghép cả 6 query vì sẽ thu được flag hai lần.

Ta deduplicate bằng sequence number:

```python
chunks[sequence] = payload
```

Sau đó sort:

```python
for sequence in sorted(chunks):
    ...
```

Đây cũng là lý do sequence number `00`, `01`, `02` rất quan trọng.

---

# 18. Indicators of Compromise – IOC

### Suspicious domain

```text
sync.cdn-telemetry-lab.net
cdn-telemetry-lab.net
```

### Suspicious query names

```text
00ja3ugvcgpm3doobx.sync.cdn-telemetry-lab.net
01mi4dmy3dg43tozru.sync.cdn-telemetry-lab.net
02gi3geoldgb6q.sync.cdn-telemetry-lab.net
```

### Behavioral IOC

- DNS label có entropy cao.
- Label mang sequence number tăng dần.
- Query lặp theo chu kỳ.
- Nhiều NXDOMAIN.
- Payload chỉ xuất hiện trong query, không cần response thành công.
- Chunk nhỏ, gửi thưa để tránh tạo anomaly lớn.

---

# 19. Detection ideas

Nếu gặp tình huống tương tự trong SOC/DFIR, có thể săn DNS exfiltration dựa trên:

### Long/high-entropy subdomains

Ví dụ query có phần subdomain dài và gần như ngẫu nhiên:

```text
ajd83jdks92kd....example.com
```

### Tỷ lệ NXDOMAIN cao

```text
client -> rất nhiều unique subdomain -> NXDOMAIN
```

### Character distribution bất thường

Ví dụ label chỉ chứa:

```text
[a-z2-7]
```

có thể là Base32.

### Sequence pattern

```text
00...
01...
02...
03...
```

### Beaconing

Các query xuất hiện theo chu kỳ đều hoặc gần đều:

```text
T0
T0 + 8s
T0 + 16s
T0 + 24s
```

### Domain mới hoặc không thuộc baseline

Một hostname có tên nghe hợp lệ như:

```text
cdn-telemetry-lab.net
```

không có nghĩa nó an toàn. Attacker thường chọn domain có tên giống telemetry/CDN/update service để giảm nghi ngờ.

---

# 20. Attack flow của challenge

```text
Unreleased design / secret
           |
           v
      Encode Base32
           |
           v
     Split into chunks
           |
           v
 Add sequence 00 / 01 / 02
           |
           v
Build DNS names
           |
           +--> 00<chunk>.sync.cdn-telemetry-lab.net
           +--> 01<chunk>.sync.cdn-telemetry-lab.net
           +--> 02<chunk>.sync.cdn-telemetry-lab.net
           |
           v
     DNS query sent
           |
           v
Attacker logs query names
           |
           v
 Sort -> strip sequence -> Base32 decode
           |
           v
H7CTF{6787b86cc777f426b9c0}
```

---

# 21. Kết luận

Điểm quan trọng nhất của bài không phải là tìm một packet chứa flag nguyên vẹn, mà là nhận ra **pattern hành vi**.

Traffic đáng ngờ:

```text
00ja3ugvcgpm3doobx.sync.cdn-telemetry-lab.net
01mi4dmy3dg43tozru.sync.cdn-telemetry-lab.net
02gi3geoldgb6q.sync.cdn-telemetry-lab.net
```

cho thấy:

- `00/01/02` là sequence number.
- phần sau sequence mang dữ liệu.
- alphabet phù hợp Base32.
- data được chia thành nhiều DNS query.
- query được gửi thưa và lặp lại.
- DNS response là NXDOMAIN nhưng không ảnh hưởng đến exfiltration.

Sau khi Base32 decode và ghép đúng thứ tự, ta thu được:

```text
H7CTF{6787b86cc777f426b9c0}
```

## Final Flag

```text
H7CTF{6787b86cc777f426b9c0}
```
