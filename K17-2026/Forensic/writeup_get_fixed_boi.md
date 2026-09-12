# K17 CTF 2026 — get fixed boi

## Thông tin thử thách

- **Tên:** get fixed boi
- **Độ khó:** Medium
- **Tệp:** `AWholeNewWorld(1).wld`
- **Chủ đề:** Forensics / định dạng tệp Terraria

## Flag

```text
K17{cr1ms0n_0r_corrup73d}
```

## 1. Phân tích ban đầu

Đề bài cho một world Terraria có phần mở rộng `.wld`, nhưng game không thể mở
được. Trước tiên, kiểm tra kích thước, mã băm và các byte đầu tệp:

```bash
file 'AWholeNewWorld(1).wld'
sha256sum 'AWholeNewWorld(1).wld'
hexdump -C -n 192 'AWholeNewWorld(1).wld'
```

Kết quả đáng chú ý:

```text
00000000  3f 01 00 00 00 00 00 00 00 00 00 03 04 00 00 00
00000010  00 00 00 00 00 00 00 00 0b 00 c6 c8 9b 4f aa 2e
```

Bốn byte đầu là số nguyên little-endian:

```text
3f 01 00 00 = 0x0000013f = 319
```

Đây là phiên bản world Terraria `319`, tương ứng với nhánh Terraria 1.4.5.

## 2. Cấu trúc header của world Terraria

Theo mã nguồn của TEdit, một world Terraria hiện đại bắt đầu bằng các trường:

| Offset | Kích thước | Ý nghĩa |
|---:|---:|---|
| `0x00` | 4 byte | Phiên bản world |
| `0x04` | 7 byte | Chuỗi nhận dạng `relogic` |
| `0x0B` | 1 byte | Loại tệp, `2` là World |
| `0x0C` | 4 byte | File revision |
| `0x10` | 8 byte | World flags |
| `0x18` | 2 byte | Số lượng section |
| `0x1A` | `4 × n` byte | Bảng con trỏ section |
| Sau bảng | 2 byte + bit array | Danh sách tile cần lưu frame |

Trong tệp thử thách có ba giá trị bị sửa:

| Offset | Giá trị trong tệp | Giá trị đúng |
|---:|---|---|
| `0x04` | `00 00 00 00 00 00 00` | ASCII `relogic` |
| `0x0B` | `03` — Map | `02` — World |
| `0x1A` | `c6 c8 9b 4f` | `a7 00 00 00` |

Con trỏ section đầu tiên phải là `0xA7`. Có thể tự tính giá trị này từ
header:

```text
4                         version
+ 7                       "relogic"
+ 1                       file type
+ 4                       revision
+ 8                       flags
+ 2                       section count
+ 11 × 4                  11 section pointers
+ 2                       tile-importance count
+ ceil(753 / 8) = 95      tile-importance bit array
--------------------------------------------------
= 167 = 0xA7
```

Ngay tại offset `0xA7` cũng xuất hiện một chuỗi hợp lệ của header world:

```text
07 63 72 69 6d 73 6f 6e
   c  r  i  m  s  o  n
```

Byte `07` là độ dài và bảy byte tiếp theo tạo thành tên world `crimson`. Điều
này xác nhận `0xA7` là đầu section chứa thông tin world.

## 3. Sửa world

Script tối thiểu để phục hồi header:

```python
#!/usr/bin/env python3
from pathlib import Path
import struct

src = Path("AWholeNewWorld(1).wld")
dst = Path("AWholeNewWorld_fixed.wld")

data = bytearray(src.read_bytes())

data[0x04:0x0B] = b"relogic"       # magic
data[0x0B] = 2                      # FileType.World
struct.pack_into("<I", data, 0x1A, 0xA7)

dst.write_bytes(data)
print(f"[+] Wrote {dst}")
```

Sau khi chạy script, header hợp lệ và các section có vị trí:

```text
0x000000a7
0x00002eaa
0x002a051b
0x002a4f8b
0x002a4f8d
0x002a4fd1
0x002a4fd5
0x002a4fd9
0x002a4fdd
0x002a4fe9
0x002a5008
```

## 4. Giải mã tile data

Thông tin world cho biết bản đồ có kích thước:

```text
width  = 4200 tiles
height = 1200 tiles
```

Tile section nằm từ `0x2EAA` đến `0x2A051B`. Terraria lưu từng cột tile và
nén các tile liên tiếp giống nhau bằng RLE.

Byte header đầu của mỗi tile có cấu trúc chính:

| Bit | Ý nghĩa |
|---:|---|
| `0` | Có header phụ |
| `1` | Có active tile |
| `2` | Có wall |
| `3–4` | Loại liquid |
| `5` | Tile ID dùng 2 byte |
| `6–7` | Kiểu lưu bộ đếm RLE |

Trình giải cần đọc các header phụ, tile ID, frame, màu, wall, liquid và cuối
cùng là bộ đếm RLE. Nếu tile có `rle = n`, tile hiện tại được lặp thêm `n` lần
theo chiều dọc.

Khi giải mã toàn bộ `4200 × 1200` tile, con trỏ đọc kết thúc tại:

```text
tile stream end = 0x2A051B
expected        = 0x2A051B
```

Hai giá trị trùng nhau chứng minh header đã được phục hồi đúng và tile data
được giải mã không lệch byte.

## 5. Dựng bản đồ và lấy flag

Ta gán một màu cố định cho mỗi tile ID rồi xuất ma trận tile thành PNG. Trên
bản đồ xuất hiện một dòng chữ rất lớn được tạo bằng các khối tile:

```text
Cr1ms0n_0r_corrupt3d
```

Đặt chuỗi này vào định dạng flag của K17 CTF:

```text
K17{cr1ms0n_0r_corrup73d}
```

## 6. Script dựng bản đồ

Script dưới đây vừa sửa file vừa giải mã tile section và tạo
`terraria_map.png`.

Cài thư viện cần thiết:

```bash
python3 -m pip install numpy pillow
```

Lưu script thành `solve.py`, đặt cạnh file challenge rồi chạy:

```bash
python3 solve.py
```

```python
#!/usr/bin/env python3
from collections import Counter
from pathlib import Path
import colorsys
import struct

import numpy as np
from PIL import Image

SOURCE = Path("AWholeNewWorld(1).wld")
FIXED = Path("AWholeNewWorld_fixed.wld")
MAP = Path("terraria_map.png")

data = bytearray(SOURCE.read_bytes())

# Phục hồi header.
data[0x04:0x0B] = b"relogic"
data[0x0B] = 2
struct.pack_into("<I", data, 0x1A, 0xA7)
FIXED.write_bytes(data)


def i16(offset):
    return struct.unpack_from("<h", data, offset)[0]


def i32(offset):
    return struct.unpack_from("<i", data, offset)[0]


# Đọc bảng section và tile-frame-importance.
section_count = i16(0x18)
sections = [i32(0x1A + 4 * i) for i in range(section_count)]

importance_count = i16(0x1A + 4 * section_count)
importance_start = 0x1C + 4 * section_count
importance_size = (importance_count + 7) // 8
importance_data = data[importance_start:importance_start + importance_size]

important = [
    bool(importance_data[i // 8] & (1 << (i % 8)))
    for i in range(importance_count)
]

width, height = 4200, 1200
tile_type = np.full((height, width), 0xFFFF, dtype=np.uint16)
wall_type = np.zeros((height, width), dtype=np.uint16)

p = sections[1]
counts = Counter()

for x in range(width):
    y = 0

    while y < height:
        header1 = data[p]
        p += 1

        header2 = header3 = header4 = 0

        if header1 & 1:
            header2 = data[p]
            p += 1

            if header2 & 1:
                header3 = data[p]
                p += 1

                if header3 & 1:
                    header4 = data[p]
                    p += 1

        current_type = 0xFFFF

        # Active tile.
        if header1 & 2:
            if header1 & 0x20:
                current_type = data[p] | (data[p + 1] << 8)
                p += 2
            else:
                current_type = data[p]
                p += 1

            # Tile cần lưu frame U/V.
            if current_type >= len(important) or important[current_type]:
                p += 4

            # Tile paint.
            if header3 & 0x08:
                p += 1

        # Wall.
        wall = 0
        if header1 & 0x04:
            wall = data[p]
            p += 1

            if header3 & 0x10:
                p += 1

        # Liquid amount.
        if header1 & 0x18:
            p += 1

        # Byte cao của wall ID.
        if header3 & 0x40:
            wall |= data[p] << 8
            p += 1

        # RLE: 0 = không nén, 1 = uint8, còn lại = int16.
        rle_kind = header1 >> 6
        if rle_kind == 0:
            rle = 0
        elif rle_kind == 1:
            rle = data[p]
            p += 1
        else:
            rle = i16(p)
            p += 2

        end = min(height, y + rle + 1)

        if current_type != 0xFFFF:
            tile_type[y:end, x] = current_type
            counts[current_type] += end - y

        if wall:
            wall_type[y:end, x] = wall

        y = end

print(f"[+] Repaired world: {FIXED}")
print(f"[+] Tile stream end: {p:#x}")
print(f"[+] Expected end:    {sections[2]:#x}")

if p != sections[2]:
    raise ValueError("Tile parser bị lệch byte")

# Dựng ảnh sơ đồ: wall màu tối, mỗi tile ID có một màu riêng.
rgb = np.zeros((height, width, 3), dtype=np.uint8)
rgb[wall_type != 0] = (28, 31, 38)

for tile_id in counts:
    hue = (tile_id * 0.61803398875) % 1.0
    saturation = 0.45 + ((tile_id * 17) % 30) / 100
    value = 0.58 + ((tile_id * 29) % 30) / 100
    color = tuple(
        int(component * 255)
        for component in colorsys.hsv_to_rgb(hue, saturation, value)
    )
    rgb[tile_type == tile_id] = color

Image.fromarray(rgb).save(MAP)
print(f"[+] Rendered map: {MAP}")
```

## 7. Kết luận

Điểm chính của thử thách là nhận ra `.wld` không phải dữ liệu ngẫu nhiên mà là
một world Terraria có header bị sửa có chủ ý. Sau khi khôi phục magic, file type
và con trỏ section đầu tiên, ta có thể giải mã RLE của tile section và nhìn thấy
flag được xây trực tiếp trong địa hình.

## Tài liệu tham khảo

- [TEdit — World.FileV2.cs](https://github.com/TEdit/Terraria-Map-Editor/blob/main/src/TEdit.Terraria/World.FileV2.cs)
- [Terraria `.wld` file format overview](https://seancode.com/terrafirma/world.html)

