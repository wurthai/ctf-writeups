# H7CTF 2026 — Adapter Cartel Writeup

## Challenge Information

- **Challenge:** Adapter Cartel
- **Category:** AI / ML Security
- **Difficulty:** Hard
- **Points:** 75
- **Flag:** `H7CTF{0ddc42ef683b6bd1be9f}`

---

## 1. Challenge Description

> You mirrored a community model hub: one base model and eight community adapters stacked on top. Each one sails through review alone, yet the scanner keeps flagging the collection and won't say why.
>
> No member ever looks guilty on its own, which is the whole point of a cartel.

Bài challenge cung cấp một base model cùng nhiều LoRA adapter. Mỗi adapter khi kiểm tra riêng đều không cho thấy payload đáng ngờ, nhưng khi các adapter được ghép lại, scanner lại phát hiện một **composable backdoor**.

Ý tưởng cốt lõi của bài là:

> Payload không tồn tại hoàn chỉnh trong bất kỳ adapter riêng lẻ nào. Nó được chia nhỏ giữa nhiều adapter và chỉ xuất hiện khi các LoRA update được cộng lại.

Đây là một dạng **additive secret sharing thông qua LoRA weights**.

---

## 2. Phân tích ban đầu

Sau khi giải nén challenge:

```bash
unzip adapter-hub.zip
cd adapter-hub
```

Ta kiểm tra cấu trúc thư mục:

```bash
find . -maxdepth 3 -type f | sort
```

Trong package có một base model và nhiều thư mục adapter, mỗi adapter thường chứa:

```text
adapter_config.json
adapter_model.safetensors
```

README của challenge đưa ra hai hint quan trọng:

1. Model có module `expert_router` với kích thước **16 × 16**.
2. Scanner cảnh báo về một **composable backdoor**.

Điều này gợi ý rằng cần kiểm tra những adapter cùng tác động lên module `expert_router`.

---

## 3. Xác định các adapter đáng chú ý

Kiểm tra `adapter_config.json` của từng adapter.

Có thể dùng:

```bash
grep -R "\"expert_router\"" adapters/*/adapter_config.json
```

Kết quả cho thấy chỉ có 4 adapter target vào `expert_router`:

```text
vendor-02-summarize-lora
vendor-03-translate-de-lora
vendor-05-rlhf-helpful-lora
vendor-07-json-mode-lora
```

Cả 4 đều có cấu hình:

```json
{
  "r": 16,
  "lora_alpha": 16
}
```

Đây là chi tiết rất quan trọng.

---

## 4. Công thức LoRA

Với LoRA, update được cộng vào trọng số gốc có dạng:

```text
ΔW = (alpha / r) × B × A
```

Trong challenge này:

```text
alpha = 16
r     = 16
```

Do đó:

```text
alpha / r = 1
```

và:

```text
ΔW = B × A
```

Khi kiểm tra tensor:

```text
expert_router.lora_A.weight
```

của cả 4 adapter, ta phát hiện `A` chính xác là ma trận identity kích thước `16 × 16`:

```text
A = I
```

Vì:

```text
B × I = B
```

nên:

```text
ΔW = B
```

Điều này có nghĩa mỗi adapter thực chất trực tiếp đóng góp một ma trận `B` vào `expert_router`.

---

## 5. Vì sao từng adapter nhìn vô hại?

Nếu xem riêng từng `B`, các giá trị chỉ giống dữ liệu ngẫu nhiên.

Ví dụ:

```text
-49   34   38   ...
 50   -9    5   ...
-37  -33   13   ...
108   63   11   ...
```

Không có chuỗi ASCII rõ ràng.

Đây chính là lý do scanner nếu chỉ kiểm tra từng adapter độc lập sẽ không nhìn thấy payload.

---

## 6. Merge các LoRA update

Ta cộng update của 4 adapter:

```text
ΔW_total =
ΔW_02 +
ΔW_03 +
ΔW_05 +
ΔW_07
```

Do mỗi adapter có:

```text
ΔW_i = B_i
```

nên:

```text
ΔW_total =
B_02 +
B_03 +
B_05 +
B_07
```

Kết quả ma trận merge bắt đầu bằng:

```text
72  55  67  84  70 123  48 100 100  99  52  50 101 102  54  56
51  98  54  98 100  49  98 101  57 102 125   0   0   0   0   0
 0   0   0   0  ...
```

Đây không còn là dữ liệu ngẫu nhiên nữa.

---

## 7. Decode ASCII

Chuyển từng số khác 0 sang ASCII:

```text
72  -> H
55  -> 7
67  -> C
84  -> T
70  -> F
123 -> {
48  -> 0
100 -> d
100 -> d
99  -> c
52  -> 4
50  -> 2
101 -> e
102 -> f
54  -> 6
56  -> 8
51  -> 3
98  -> b
54  -> 6
98  -> b
100 -> d
49  -> 1
98  -> b
101 -> e
57  -> 9
102 -> f
125 -> }
```

Ghép lại:

```text
H7CTF{0ddc42ef683b6bd1be9f}
```

---

## 8. Flag

```text
H7CTF{0ddc42ef683b6bd1be9f}
```

---

## 9. Script solve hoàn chỉnh

Không cần cài `transformers`, `peft` hay load toàn bộ model.

Ta chỉ cần parse trực tiếp file `.safetensors`.

Tạo file:

```bash
nano solve.py
```

Nội dung:

```python
import os
import glob
import json
import struct
import numpy as np

ROOT = "adapters"


def load_safetensors(path):
    tensors = {}

    with open(path, "rb") as f:
        # 8 byte đầu tiên chứa độ dài JSON header
        header_len = struct.unpack("<Q", f.read(8))[0]

        header = json.loads(
            f.read(header_len)
        )

        data_start = 8 + header_len

        for name, info in header.items():
            if name == "__metadata__":
                continue

            start, end = info["data_offsets"]

            f.seek(data_start + start)
            raw = f.read(end - start)

            arr = np.frombuffer(
                raw,
                dtype="<f4"
            ).copy()

            arr = arr.reshape(info["shape"])
            tensors[name] = arr

    return tensors


merged = None

for directory in sorted(glob.glob(f"{ROOT}/*")):

    config_path = os.path.join(
        directory,
        "adapter_config.json"
    )

    model_path = os.path.join(
        directory,
        "adapter_model.safetensors"
    )

    with open(config_path) as f:
        config = json.load(f)

    # Chỉ quan tâm adapter tác động vào expert_router
    if "expert_router" not in config["target_modules"]:
        continue

    print("[+] Router adapter:", directory)

    tensors = load_safetensors(model_path)

    A = None
    B = None

    for name, tensor in tensors.items():

        if "expert_router.lora_A.weight" in name:
            A = tensor

        if "expert_router.lora_B.weight" in name:
            B = tensor

    # Công thức LoRA
    scale = config["lora_alpha"] / config["r"]

    delta = scale * (B @ A)

    if merged is None:
        merged = delta
    else:
        merged += delta


print("\n[+] Merged router:")
print(merged)

# Flatten theo row-major
values = np.rint(merged.flatten()).astype(int)

# Các byte khác 0 chính là payload
payload = bytes(
    x for x in values
    if x != 0 and 0 <= x <= 255
)

print("\n[+] Payload:", payload)
print("[+] Flag:", payload.decode())
```

Chạy:

```bash
python3 solve.py
```

Kết quả:

```text
[+] Payload: b'H7CTF{0ddc42ef683b6bd1be9f}'
[+] Flag: H7CTF{0ddc42ef683b6bd1be9f}
```

---

## 10. Phân tích kỹ thuật `safetensors`

File `safetensors` có format khá đơn giản.

### 10.1. Header length

8 byte đầu tiên là một unsigned integer little-endian:

```python
header_len = struct.unpack("<Q", f.read(8))[0]
```

Giá trị này cho biết độ dài JSON header.

### 10.2. JSON header

Tiếp theo là JSON mô tả từng tensor:

```python
header = json.loads(
    f.read(header_len)
)
```

Mỗi tensor chứa thông tin như:

```json
{
  "dtype": "F32",
  "shape": [16, 16],
  "data_offsets": [0, 1024]
}
```

### 10.3. Đọc raw tensor

Dữ liệu tensor nằm sau header:

```python
data_start = 8 + header_len
```

Sau đó dùng offset để đọc:

```python
start, end = info["data_offsets"]

f.seek(data_start + start)
raw = f.read(end - start)
```

Vì tensor sử dụng float32:

```python
arr = np.frombuffer(
    raw,
    dtype="<f4"
)
```

Cuối cùng reshape theo `shape` trong header:

```python
arr = arr.reshape(info["shape"])
```

---

## 11. Ý tưởng của tác giả

Challenge sử dụng một kỹ thuật tương đương **additive secret sharing**.

Giả sử secret matrix là:

```text
S
```

Tác giả tạo 4 ma trận:

```text
B02
B03
B05
B07
```

sao cho:

```text
B02 + B03 + B05 + B07 = S
```

Nhưng mỗi ma trận riêng lẻ được chọn sao cho trông như noise.

Ví dụ:

```text
B02 -> random-looking matrix
B03 -> random-looking matrix
B05 -> random-looking matrix
B07 -> random-looking matrix
```

Không ma trận nào chứa flag trực tiếp.

Chỉ khi merge:

```text
random1
+ random2
+ random3
+ random4
----------------
ASCII payload
```

payload mới xuất hiện.

---

## 12. Tại sao đây là composable backdoor?

Một security scanner truyền thống có thể xử lý từng LoRA adapter độc lập:

```text
scan(adapter_02)
scan(adapter_03)
scan(adapter_05)
scan(adapter_07)
```

Và kết luận:

```text
clean
clean
clean
clean
```

Nhưng điều scanner cần kiểm tra thực tế là composition:

```text
scan(
    adapter_02 +
    adapter_03 +
    adapter_05 +
    adapter_07
)
```

Lúc đó payload mới xuất hiện.

Đây chính là vấn đề của **composable ML artifacts**:

> Một artifact có thể an toàn khi đứng riêng, nhưng trở nên độc hại khi kết hợp với artifact khác.

---

## 13. Ý nghĩa tên challenge

Tên **Adapter Cartel** là một hint khá trực tiếp.

Mỗi adapter là một "thành viên".

Không thành viên nào trông có vẻ đáng ngờ khi đứng một mình:

> "No member ever looks guilty on its own."

Nhưng khi toàn bộ "cartel" phối hợp, payload được tái tạo.

Nói cách khác:

```text
member 1 -> harmless
member 2 -> harmless
member 3 -> harmless
member 4 -> harmless

member 1 + 2 + 3 + 4 -> backdoor payload
```

---

## 14. Tổng kết

Luồng giải bài:

```text
README
   |
   v
expert_router 16x16
   |
   v
kiểm tra adapter_config.json
   |
   v
tìm 4 adapter cùng target expert_router
   |
   v
r = 16, alpha = 16
   |
   v
scale = 1
   |
   v
A = Identity
   |
   v
ΔW = B
   |
   v
cộng 4 ma trận B
   |
   v
ASCII values
   |
   v
FLAG
```

Điểm thú vị nhất của challenge là payload không được giấu bằng encoding hay encryption truyền thống.

Nó được giấu ngay trong **quan hệ toán học giữa các LoRA adapter**.

Đây là một ví dụ rất hay về:

- LoRA internals
- model supply-chain security
- composable backdoors
- additive secret sharing
- safetensors parsing
- security risk khi scan ML artifact độc lập

---

## Final Flag

```text
H7CTF{0ddc42ef683b6bd1be9f}
```
