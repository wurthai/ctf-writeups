# Model Package Autopsy – Write-up

## 1. Thông tin challenge

**Tên bài:** Model Package Autopsy  
**Category:** AI / ML Security / Forensics  
**Độ khó:** Easy  
**Điểm:** 25

### Description

> Meridian's ML team pulled a fine-tuned model off an internal build agent and queued it straight for production. The operator who packaged it left something off the changelog.
>
> Consider this the postmortem.

File được cung cấp:

```text
sentiment-distilbert-meridian.zip
```

Mục tiêu của challenge là kiểm tra package của một model machine learning và tìm ra thứ bất thường đã bị người đóng gói model cố tình để lại.

---

## 2. Ý tưởng ban đầu

Đây là một model DistilBERT được fine-tune và đóng gói dưới dạng PyTorch.

Các model PyTorch cũ thường được lưu bằng:

```python
torch.save()
```

và load bằng:

```python
torch.load()
```

Điểm đáng chú ý là `torch.load()` truyền thống sử dụng cơ chế serialization dựa trên Python `pickle`.

`pickle` không chỉ lưu dữ liệu mà còn có thể chứa các instruction gọi function trong quá trình deserialize.

Vì vậy, nếu file model đến từ nguồn không đáng tin cậy, việc chạy:

```python
torch.load("pytorch_model.bin", weights_only=False)
```

có thể dẫn tới arbitrary code execution.

Do đó, ta sẽ phân tích file model **tĩnh**, không load trực tiếp nó.

---

## 3. Giải nén challenge

Đầu tiên kiểm tra file:

```bash
ls -lh
```

Ta có:

```text
sentiment-distilbert-meridian.zip
```

Kiểm tra loại file:

```bash
file sentiment-distilbert-meridian.zip
```

Liệt kê nội dung mà chưa giải nén:

```bash
unzip -l sentiment-distilbert-meridian.zip
```

Package gồm ba file chính:

```text
README.md
config.json
pytorch_model.bin
```

Giải nén:

```bash
mkdir model_autopsy
unzip sentiment-distilbert-meridian.zip -d model_autopsy
cd model_autopsy
```

Kiểm tra:

```bash
ls -lah
```

---

## 4. Đọc README

```bash
cat README.md
```

Nội dung đáng chú ý:

```python
import torch
ckpt = torch.load('pytorch_model.bin', weights_only=False)
print(ckpt['val_accuracy'])
```

Dòng đáng chú ý nhất là:

```python
torch.load('pytorch_model.bin', weights_only=False)
```

`weights_only=False` cho phép PyTorch deserialize các Python object trong checkpoint thay vì chỉ đọc tensor weight an toàn hơn.

Nếu checkpoint chứa malicious pickle object thì code có thể được thực thi ngay khi load.

Vì vậy **không chạy đoạn Python trong README**.

---

## 5. Kiểm tra config.json

```bash
cat config.json
```

Nội dung cho thấy đây là một model sentiment classification DistilBERT với hai nhãn:

```text
negative
positive
```

Không có flag hay thông tin đáng chú ý trong `config.json`.

Vì vậy tập trung vào:

```text
pytorch_model.bin
```

---

## 6. Kiểm tra pytorch_model.bin

Không chạy file mà trước tiên dùng:

```bash
file pytorch_model.bin
```

Kết quả cho thấy đây là một ZIP archive.

Có thể xem nội dung bằng:

```bash
unzip -l pytorch_model.bin
```

Ta thấy file quan trọng:

```text
pytorch_model/data.pkl
```

Ngoài ra còn có các tensor storage như:

```text
pytorch_model/data/0
pytorch_model/data/1
pytorch_model/data/2
pytorch_model/data/3
```

Trong đó:

- `data/*` chủ yếu chứa tensor storage.
- `data.pkl` chứa object graph và các pickle instruction dùng để tái tạo checkpoint.

---

## 7. Extract checkpoint mà không load

Tạo thư mục:

```bash
mkdir inner
```

Extract:

```bash
unzip pytorch_model.bin -d inner
```

Kiểm tra:

```bash
find inner -type f
```

Ta thấy:

```text
inner/pytorch_model/data.pkl
inner/pytorch_model/data/0
inner/pytorch_model/data/1
inner/pytorch_model/data/2
inner/pytorch_model/data/3
```

---

## 8. Phân tích pickle một cách an toàn

Python có module:

```text
pickletools
```

cho phép disassemble pickle mà không thực hiện các function chứa trong đó.

Chạy:

```bash
python3 -m pickletools inner/pytorch_model/data.pkl
```

Có thể lọc các opcode đáng chú ý:

```bash
python3 -m pickletools inner/pytorch_model/data.pkl \
| grep -nE "GLOBAL|REDUCE|eval|exec|base64|zlib"
```

Xuất hiện các chuỗi đáng ngờ như:

```text
GLOBAL '__builtin__ eval'
BINUNICODE "exec(__import__('zlib').decompress(__import__('base64').b64decode('...')).decode())"
REDUCE
```

Đây là bằng chứng checkpoint có payload bất thường.

---

## 9. Phân tích opcode nguy hiểm

Phần cuối của pickle có dạng:

```text
GLOBAL '__builtin__ eval'
BINUNICODE "exec(__import__('zlib').decompress(__import__('base64').b64decode('...')).decode())"
TUPLE1
REDUCE
```

### GLOBAL

```text
GLOBAL '__builtin__ eval'
```

yêu cầu pickle lấy function:

```python
eval
```

### BINUNICODE

Sau đó pickle push chuỗi Python:

```python
exec(
    __import__('zlib').decompress(
        __import__('base64').b64decode('...')
    ).decode()
)
```

### TUPLE1

Biến chuỗi trên thành argument tuple.

### REDUCE

Opcode `REDUCE` gần tương đương với việc gọi:

```python
eval("exec(...)")
```

Tức là trong quá trình unpickle, Python có thể thực sự gọi `eval()` rồi thực thi payload bằng `exec()`.

Chuỗi thực thi:

```text
pickle
   ↓
GLOBAL eval
   ↓
REDUCE
   ↓
eval()
   ↓
exec()
   ↓
base64 decode
   ↓
zlib decompress
   ↓
Python payload
```

Đây chính là malicious pickle / model serialization backdoor.

---

## 10. Xem khu vực đáng ngờ trong pickle

Có thể dùng:

```bash
python3 -m pickletools inner/pytorch_model/data.pkl \
| sed -n '195,222p'
```

Tại đây sẽ thấy các opcode liên quan tới:

```text
GLOBAL '__builtin__ eval'
BINUNICODE "exec(...)"
TUPLE1
REDUCE
```

Tên `_extra_state` cũng là một hint đáng chú ý, cho thấy payload được nhét vào phần extra state thay vì tensor weights.

---

## 11. Decode payload mà không thực thi

Ta tuyệt đối không cần chạy `eval()` hoặc `exec()`.

Payload chỉ được encode bằng:

```text
Base64
   ↓
zlib
```

Tạo script:

```bash
nano decode.py
```

Nội dung:

```python
import re
import base64
import zlib

with open("inner/pytorch_model/data.pkl", "rb") as f:
    data = f.read()

match = re.search(
    rb"b64decode\('([^']+)'\)",
    data
)

if not match:
    print("Payload not found")
    exit()

encoded = match.group(1)

compressed = base64.b64decode(encoded)

payload = zlib.decompress(compressed)

print(payload.decode())
```

Chạy:

```bash
python3 decode.py
```

Kết quả:

```python
# meridian-ml build agent :: post-load hook (do not ship)
import os, urllib.request

OPERATOR = 'H7CTF{64080f42b43c8e48033c}'

def _beacon():
    # would exfil os.environ + host info to the operator relay; neutered in this build
    return OPERATOR

_beacon()
```

Ta thấy flag:

```text
H7CTF{64080f42b43c8e48033c}
```

---

## 12. Decode nhanh bằng một lệnh

Không cần tạo file Python, có thể dùng:

```bash
python3 - <<'PY'
import re
import base64
import zlib

p = open(
    "inner/pytorch_model/data.pkl",
    "rb"
).read()

x = re.search(
    rb"b64decode\('([^']+)'\)",
    p
).group(1)

print(
    zlib.decompress(
        base64.b64decode(x)
    ).decode()
)
PY
```

Output:

```python
# meridian-ml build agent :: post-load hook (do not ship)
import os, urllib.request

OPERATOR = 'H7CTF{64080f42b43c8e48033c}'

def _beacon():
    # would exfil os.environ + host info to the operator relay; neutered in this build
    return OPERATOR

_beacon()
```

---

## 13. Ý nghĩa payload

Payload import:

```python
import os, urllib.request
```

và có comment:

```text
would exfil os.environ + host info to the operator relay
```

Điều này cho thấy phiên bản ban đầu của payload được thiết kế để thu thập thông tin môi trường và máy host.

Trong môi trường CI/CD hoặc ML build agent, environment variable có thể chứa dữ liệu nhạy cảm như:

```text
API keys
cloud credentials
CI/CD tokens
Git credentials
deployment secrets
model registry credentials
```

Tuy nhiên challenge ghi:

```text
neutered in this build
```

nghĩa là phần exfiltration thực tế đã bị vô hiệu hóa trong bản challenge.

---

## 14. Liên hệ với description

Challenge nói:

> The operator who packaged it left something off the changelog.

Thứ bị bỏ khỏi changelog chính là:

```text
post-load hook
```

được giấu bên trong PyTorch checkpoint.

Payload xác nhận bằng dòng:

```python
# meridian-ml build agent :: post-load hook (do not ship)
```

`do not ship` cho thấy đoạn code này đáng lẽ không được đưa vào production artifact.

---

## 15. Tại sao README là một cái bẫy?

README hướng dẫn:

```python
import torch

ckpt = torch.load(
    'pytorch_model.bin',
    weights_only=False
)

print(ckpt['val_accuracy'])
```

Nếu làm theo, checkpoint sẽ được deserialize.

Do pickle chứa:

```text
GLOBAL '__builtin__ eval'
```

và:

```text
REDUCE
```

thì quá trình `torch.load()` có thể thực thi arbitrary Python code.

Tức là:

```python
torch.load(...)
```

không chỉ đơn thuần là đọc weights.

---

## 16. Vì sao pickle nguy hiểm?

Ví dụ đơn giản:

```python
class Evil:
    def __reduce__(self):
        return (eval, ("print('code execution')",))
```

Khi object này được unpickle, Python có thể thực hiện:

```python
eval("print('code execution')")
```

Challenge sử dụng đúng nguyên lý này nhưng payload được che bằng Base64 + zlib.

---

## 17. Dấu hiệu nhận biết model độc hại

Các indicator đáng chú ý trong bài:

### 1. README yêu cầu

```python
weights_only=False
```

### 2. Checkpoint chứa `data.pkl`

PyTorch dùng pickle metadata bên trong package.

### 3. Có `GLOBAL eval`

```text
GLOBAL '__builtin__ eval'
```

Một checkpoint model bình thường gần như không có lý do gì để gọi `eval()`.

### 4. Có `exec`

Payload chứa:

```python
exec(...)
```

### 5. Có obfuscation

```python
base64.b64decode(...)
zlib.decompress(...)
```

### 6. Có module mạng

```python
urllib.request
```

kết hợp với comment về exfiltration cho thấy mục tiêu ban đầu là beacon / exfiltration.

---

## 18. Chuỗi lệnh solve nhanh toàn bài

```bash
unzip sentiment-distilbert-meridian.zip -d model_autopsy
```

```bash
cd model_autopsy
```

```bash
cat README.md
```

```bash
file pytorch_model.bin
```

```bash
unzip -l pytorch_model.bin
```

```bash
mkdir inner
unzip pytorch_model.bin -d inner
```

```bash
python3 -m pickletools inner/pytorch_model/data.pkl \
| grep -nE "GLOBAL|REDUCE|eval|exec|base64|zlib"
```

Decode:

```bash
python3 - <<'PY'
import re
import base64
import zlib

p = open(
    "inner/pytorch_model/data.pkl",
    "rb"
).read()

x = re.search(
    rb"b64decode\('([^']+)'\)",
    p
).group(1)

print(
    zlib.decompress(
        base64.b64decode(x)
    ).decode()
)
PY
```

Flag:

```text
H7CTF{64080f42b43c8e48033c}
```

---

## 19. Flag

```text
H7CTF{64080f42b43c8e48033c}
```

---

## 20. Kết luận

Challenge minh họa một vấn đề quan trọng trong bảo mật chuỗi cung ứng Machine Learning: model artifact không nhất thiết chỉ chứa numerical weights.

File:

```text
pytorch_model.bin
```

có thể chứa serialized Python objects.

Trong bài này, `data.pkl` chứa pickle instruction gọi:

```python
eval()
```

sau đó thực thi một payload được obfuscate bằng:

```text
Base64 + zlib
```

Payload được mô tả là một:

```text
post-load hook
```

từ Meridian ML build agent, với mục đích ban đầu là thu thập environment variable và host information.

Cách giải an toàn:

```text
Inspect ZIP
→ Extract data.pkl
→ pickletools disassembly
→ tìm GLOBAL eval / REDUCE
→ extract Base64
→ Base64 decode
→ zlib decompress
→ đọc payload
→ lấy flag
```

**Flag cuối cùng:**

```text
H7CTF{64080f42b43c8e48033c}
```
