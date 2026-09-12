# K17 CTF - monoid

## Challenge Information

- Name: `monoid`
- Category: Reverse Engineering / Cryptography
- Difficulty: Medium
- Points: 104

## Description

> There's this really cool fractal I like, but someone encrypted its parameters, even worse they wrote it in haskell, find the parameters to get the flag; glhf

Challenge cung cấp các file:

- `Main.dump-simpl`
- `Main.dump-asm`
- `out.txt`

Mục tiêu là tìm các tham số fractal bị mã hóa để lấy flag.

---

# 1. Initial Analysis

File `out.txt` chứa hình fractal dạng ASCII.

Quan sát dữ liệu:

```
+@=++:+@==-....**#@
@=:=-:+@+:.....:*%:@
...
```

Điều này cho thấy chương trình đang sinh một fractal và render ra terminal.

Challenge nói:

> encrypted its parameters

=> Cần reverse chương trình để tìm các tham số đầu vào.

---

# 2. Analyze Haskell Code

Do challenge được viết bằng Haskell, sử dụng:

```
Main.dump-simpl
```

để xem logic sau khi compiler tối ưu.

Tìm thấy đoạn:

```haskell
zipWith (\c k -> unsubsChar (xorChar k c))
        ct
        (cycle key)
```

Có thể suy ra thuật toán giải mã:

1. Lặp key bằng `cycle`
2. XOR ciphertext với key
3. Trừ offset ASCII bằng `unsubsChar`

---

# 3. Encryption Scheme

Ciphertext:

```
2d55090d4f576242655d24030705490250210748502d54111f4450065f0f010704041d5f6024485b500851457a5201384c68255b000613351141070859560b4a1c03094a0e1a505007471d0e0749080a5442074818160e48170f56
```

Key:

```
#!s3kur1ty
```

Hàm decrypt:

```haskell
xorChar a b = chr (ord a `xor` ord b)

unsubsChar c = chr ((ord c - 67) mod 128)

decipher ct key =
    zipWith (\c k -> unsubsChar (xorChar k c))
            ct
            (cycle key)
```

---

# 4. Python Decoder

```python
ct = bytes.fromhex(
"2d55090d4f576242655d24030705490250210748502d54111f4450065f0f010704041d5f6024485b500851457a5201384c68255b000613351141070859560b4a1c03094a0e1a505007471d0e0749080a5442074818160e48170f56"
)

key = b"#!s3kur1ty"

flag = ''.join(
    chr(((c ^ key[i % len(key)]) - 67) % 128)
    for i, c in enumerate(ct)
)

print(flag)
```

---

# 5. Decryption Result

Output:

```
K17{a_M0NaD_1s_4_M0n0Id_1n_th3_c4t3gORy_0f_3Nd0FuNC70r5}

-0.745643887 0.113825904 180 96 32
```

Ta thu được:

- Flag
- Các tham số fractal

---

# 6. Fractal Parameters

Parameters:

```
c_real = -0.745643887
c_imag =  0.113825904

iterations = 180

width  = 96
height = 32
```

Đây là tham số của Julia fractal:

```
z(n+1) = z(n)^2 + c
```

với:

```
c = -0.745643887 + 0.113825904i
```

---

# 7. Flag

```
K17{a_M0NaD_1s_4_M0n0Id_1n_th3_c4t3gORy_0f_3Nd0FuNC70r5}
```

---

# 8. Conclusion

Challenge yêu cầu:

- Reverse Haskell compiled output
- Tìm hàm decrypt
- Nhận diện XOR cipher
- Recover fractal parameters

Điểm khó nhất là đọc Haskell optimized dump.

Sau khi tìm được:

```haskell
zipWith
cycle key
xor
```

thì việc giải mã trở nên đơn giản.

Tên challenge là một trò chơi chữ:

```
Monad -> Monoid
```

liên quan đến Haskell và Category Theory.
