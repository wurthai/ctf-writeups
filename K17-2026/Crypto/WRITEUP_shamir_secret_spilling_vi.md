# K17 CTF – shamir secret spilling

## Thông tin thử thách

- Tên: `shamir secret spilling`
- Thể loại: Crypto
- Độ khó: Medium
- Flag format: `K17{...}`

## 1. Phân tích mã nguồn

Hai đa thức được sử dụng trong thử thách:

- `P` có 16 hệ số, tức bậc tối đa là 15.
- `Q` có 32 hệ số, tức bậc tối đa là 31.

File output cung cấp:

- 16 share cũ trong `known`.
- 8 share mới trong `new`.
- Modulus `MOD`.
- Cận `B` cho sai lệch giữa các hệ số của `P` và `Q`.

Phần quan trọng của chương trình:

```python
for x, px in known:
    assert polynomial_eval(P, x) == px
    assert polynomial_eval(Q, x) == px

for x, qx in new:
    assert polynomial_eval(Q, x) == qx

for pc, qc in zip(P + [0] * 16, Q):
    assert abs(centered(qc - pc)) < B
```

Như vậy, 16 share cũ đồng thời hợp lệ đối với cả `P` và `Q`. Ngoài ra, từng hệ số của `Q` chỉ lệch một lượng nhỏ hơn `B` so với hệ số tương ứng của `P`.

Đây chính là lỗi do cơ chế “backwards compatibility”: đa thức mới vẫn phải đi qua toàn bộ các điểm của đa thức cũ, trong khi sai lệch hệ số lại bị giới hạn rất nhỏ.

## 2. Khôi phục đa thức cũ

Vì `P` có bậc tối đa 15 và ta có đúng 16 điểm khác nhau nên có thể khôi phục toàn bộ `P` bằng nội suy Lagrange:

\[
P(X)=\sum_{i=0}^{15}p_iX^i \pmod{MOD}.
\]

Sau bước này, ta biết toàn bộ hệ số của `P`.

## 3. Khai thác 16 share dùng chung

Đặt:

\[
D(X)=Q(X)-P(X).
\]

Với mỗi share cũ \((x_i,p_i)\), ta có:

\[
Q(x_i)=P(x_i).
\]

Do đó:

\[
D(x_i)=0.
\]

Như vậy `D` có 16 nghiệm đã biết. Đặt:

\[
R(X)=\prod_{i=1}^{16}(X-x_i).
\]

Vì `D` có bậc tối đa 31 và `R` có bậc 16 nên tồn tại đa thức `S` có bậc tối đa 15 sao cho:

\[
D(X)=R(X)S(X).
\]

Hay:

\[
Q(X)=P(X)+R(X)S(X).
\]

## 4. Sử dụng 8 share mới

Với mỗi share mới \((y_j,q_j)\), ta tính được:

\[
S(y_j)=\frac{q_j-P(y_j)}{R(y_j)}\pmod{MOD}.
\]

Từ 8 giá trị trên, nội suy được một đa thức `S0` có bậc nhỏ hơn 8.

Đặt tiếp:

\[
T(X)=\prod_{j=1}^{8}(X-y_j).
\]

Mọi đa thức `S` bậc tối đa 15 thỏa mãn 8 điểm mới đều có dạng:

\[
S(X)=S_0(X)+T(X)U(X),
\]

trong đó:

\[
\deg U<8.
\]

Ta chỉ còn phải tìm 8 hệ số của `U`.

Thay vào biểu thức của `D`:

\[
D(X)=R(X)S_0(X)+R(X)T(X)U(X).
\]

Đặt:

\[
A(X)=R(X)T(X).
\]

Khi đó:

\[
D(X)=D_0(X)+A(X)U(X)\pmod{MOD},
\]

với \(D_0=RS_0\).

## 5. Chuyển thành bài toán lattice

Viết:

\[
U(X)=u_0+u_1X+\cdots+u_7X^7.
\]

Gọi `a_j` là vector 32 hệ số của \(X^jA(X)\), còn `d0` là vector hệ số của \(D_0\). Vector hệ số của `D` có dạng:

\[
d=d_0+\sum_{j=0}^{7}u_ja_j\pmod{MOD}.
\]

Theo điều kiện trong source, sau khi đưa về đại diện centered:

\[
|d_i|<B\quad\text{với mọi }i.
\]

`MOD` có 512 bit trong khi `B` chỉ có 273 bit. Vì vậy vector đúng cực kỳ ngắn so với một vector ngẫu nhiên modulo `MOD`.

Chọn hệ số cân bằng:

\[
K=\left\lceil\frac{MOD}{B}\right\rceil.
\]

Dựng lattice 40 chiều từ các vector hàng:

\[
(e_j, K a_j),\qquad 0\le j<8,
\]

và:

\[
(0,K\cdot MOD\cdot e_i),\qquad 0\le i<32.
\]

Target của bài toán CVP là:

\[
t=(0_8,-Kd_0).
\]

Với nghiệm đúng, hiệu giữa một điểm lattice và target có dạng:

\[
(u_0,\ldots,u_7,Kd_0,\ldots,Kd_{31}),
\]

trong đó mọi \(d_i\) đều nhỏ hơn `B`. Ta dùng LLL để rút gọn cơ sở rồi dùng CVP để tìm điểm lattice gần target nhất.

## 6. Solver hoàn chỉnh

Cài thư viện cần thiết:

```bash
python3 -m pip install fpylll cysignals
```

Solver:

```python
#!/usr/bin/env python3

import argparse
import ast
import re
from pathlib import Path

from fpylll import CVP, IntegerMatrix, LLL


def parse_output(path):
    text = Path(path).read_text(encoding="utf-8")
    modulus = int(re.search(r"MOD = (\d+)", text).group(1))
    bound = int(re.search(r"B = (\d+)", text).group(1))
    known = ast.literal_eval(
        re.search(r"known = (\[.*?\])\s*\n\s*new", text, re.S).group(1)
    )
    new = ast.literal_eval(
        re.search(r"new = (\[.*\])\s*$", text, re.S).group(1)
    )
    return modulus, bound, known, new


def trim(poly):
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def poly_add(a, b, modulus):
    result = [0] * max(len(a), len(b))
    for i in range(len(result)):
        result[i] = (
            (a[i] if i < len(a) else 0)
            + (b[i] if i < len(b) else 0)
        ) % modulus
    return trim(result)


def poly_mul(a, b, modulus):
    result = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            result[i + j] = (
                result[i + j] + x * y
            ) % modulus
    return trim(result)


def poly_scale(poly, scalar, modulus):
    return [(x * scalar) % modulus for x in poly]


def poly_eval(poly, x, modulus):
    result = 0
    for coefficient in reversed(poly):
        result = (result * x + coefficient) % modulus
    return result


def interpolate(points, modulus):
    result = [0]
    for i, (xi, yi) in enumerate(points):
        numerator = [1]
        denominator = 1

        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            numerator = poly_mul(
                numerator,
                [(-xj) % modulus, 1],
                modulus,
            )
            denominator = denominator * (xi - xj) % modulus

        factor = yi * pow(denominator, -1, modulus) % modulus
        result = poly_add(
            result,
            poly_scale(numerator, factor, modulus),
            modulus,
        )

    return result


def polynomial_with_roots(xs, modulus):
    result = [1]
    for x in xs:
        result = poly_mul(
            result,
            [(-x) % modulus, 1],
            modulus,
        )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", default="out.txt")
    args = parser.parse_args()

    modulus, bound, known, new = parse_output(args.output)

    # Khôi phục P từ 16 share cũ.
    old_poly = interpolate(known, modulus)
    assert all(
        poly_eval(old_poly, x, modulus) == y
        for x, y in known
    )

    # D = Q-P có 16 nghiệm cũ nên D = R*S.
    old_roots = polynomial_with_roots(
        [x for x, _ in known], modulus
    )

    s_points = []
    for x, qx in new:
        difference_at_x = (
            qx - poly_eval(old_poly, x, modulus)
        ) % modulus

        sx = difference_at_x * pow(
            poly_eval(old_roots, x, modulus),
            -1,
            modulus,
        )
        s_points.append((x, sx % modulus))

    # S = S0 + T*U với deg(U) < 8.
    s0 = interpolate(s_points, modulus)
    new_roots = polynomial_with_roots(
        [x for x, _ in new], modulus
    )

    all_roots = poly_mul(old_roots, new_roots, modulus)
    base_difference = poly_mul(old_roots, s0, modulus)
    base_difference += [0] * (32 - len(base_difference))

    unknown_count = 8
    coefficient_count = 32
    scale = (modulus + bound - 1) // bound

    lattice = IntegerMatrix(
        unknown_count + coefficient_count,
        unknown_count + coefficient_count,
    )

    for j in range(unknown_count):
        lattice[j, j] = 1
        for i, coefficient in enumerate(all_roots):
            lattice[j, unknown_count + i + j] = (
                scale * coefficient
            )

    for i in range(coefficient_count):
        lattice[unknown_count + i, unknown_count + i] = (
            scale * modulus
        )

    target = (
        [0] * unknown_count
        + [-scale * x for x in base_difference]
    )

    print("[*] Reducing lattice...")
    LLL.reduction(lattice, delta=0.99)
    closest = list(
        CVP.closest_vector(lattice, target, method="fast")
    )
    u_coefficients = closest[:unknown_count]

    difference = []
    for i in range(coefficient_count):
        value = base_difference[i]
        for j, uj in enumerate(u_coefficients):
            k = i - j
            if 0 <= k < len(all_roots):
                value += all_roots[k] * uj

        value %= modulus
        if value > modulus // 2:
            value -= modulus
        difference.append(value)

    # Kiểm tra điều kiện hệ số nhỏ.
    assert all(abs(x) < bound for x in difference)

    new_poly = [
        (
            (old_poly[i] if i < len(old_poly) else 0)
            + difference[i]
        ) % modulus
        for i in range(32)
    ]

    # Kiểm tra lại toàn bộ 24 share.
    assert all(
        poly_eval(new_poly, x, modulus) == y
        for x, y in known + new
    )

    secret = new_poly[0]
    flag = secret.to_bytes(
        (secret.bit_length() + 7) // 8,
        "big",
    ).decode()

    print(f"[+] {flag}")


if __name__ == "__main__":
    main()
```

Lưu code thành `solve.py`, đặt cùng thư mục với file output rồi chạy:

```bash
python3 solve.py "out.txt"
```

Nếu đang sử dụng môi trường Sage:

```bash
sage -python solve.py "out.txt"
```

## 7. Kết quả

Chương trình in ra:

```text
[*] Reducing lattice...
[+] K17{0ur_cl1ent5_r3ally_d0nt_like_r0tating_their_keys!}
```

Flag cuối cùng:

```text
K17{0ur_cl1ent5_r3ally_d0nt_like_r0tating_their_keys!}
```

## 8. Kết luận

Việc giữ nguyên toàn bộ 16 share cũ khiến hiệu `Q-P` có 16 nghiệm công khai. Đồng thời, giới hạn sai lệch hệ số bằng `B` làm nghiệm cần tìm trở thành một vector rất ngắn trong lattice. Kết hợp nội suy đa thức với LLL/CVP cho phép khôi phục hoàn toàn đa thức mới và lấy secret tại `Q(0)` dù chỉ có 8 trong số 32 share mới.
