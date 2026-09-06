# Patch Tuesday - Writeup

## Challenge Information

-   **Challenge:** Patch Tuesday
-   **Category:** Reverse Engineering
-   **Difficulty:** Beginner
-   **Author:** hoover
-   **Platform:** Windows x64 PE

## Description

Challenge này giới thiệu kỹ thuật **dynamic debugging** và **patching**
trong reverse engineering.

File `.exe` được cung cấp hứa hẹn sẽ trả về flag, nhưng chương trình
không đi theo nhánh mong muốn. Nhiệm vụ là phân tích đoạn code kiểm tra
điều kiện, thay đổi conditional jump để ép chương trình chạy vào nhánh
lấy flag.

------------------------------------------------------------------------

# 1. Kiểm tra file

Sau khi giải nén:

    rev_patch-tuesday/
    └── free-flag.exe

Kiểm tra loại file:

``` bash
file free-flag.exe
```

Kết quả:

    PE32+ executable (x86-64)

Đây là chương trình Windows 64-bit.

------------------------------------------------------------------------

# 2. Phân tích bằng debugger

Mở file bằng **x64dbg**.

Đi theo luồng thực thi, ta tìm được đoạn code quyết định việc nhận flag:

``` asm
mov ecx, DWORD PTR [rsp+34h]
call check

test eax,eax
je  success
jmp fail
```

Chương trình gọi hàm kiểm tra, sau đó dựa vào giá trị trả về trong `EAX`
để quyết định nhánh.

------------------------------------------------------------------------

# 3. Phân tích hàm kiểm tra

Hàm kiểm tra:

``` asm
xor eax,eax
cmp ecx,1337h
sete al
ret
```

Tương đương với C:

``` c
int check(int value)
{
    return value == 0x1337;
}
```

Nếu giá trị đúng:

    EAX = 1

Nếu sai:

    EAX = 0

Sau đó chương trình dùng:

``` asm
test eax,eax
je success
```

để kiểm tra.

------------------------------------------------------------------------

# 4. Patch Conditional Jump

Instruction ban đầu:

``` asm
test eax,eax
je success
```

Opcode:

    74 xx

`JE` có nghĩa:

    Jump if Equal

Tức chỉ nhảy khi Zero Flag được bật.

Ta thay đổi jump này để luôn đi vào nhánh thành công.

Có hai cách:

## Cách 1: Patch thành JMP

Thay:

``` asm
JE success
```

bằng:

``` asm
JMP success
```

## Cách 2: NOP instruction

Thay byte:

    74 xx

thành:

    90 90

`NOP` khiến chương trình bỏ qua kiểm tra.

------------------------------------------------------------------------

# 5. Giải mã flag

Sau khi đi vào nhánh thành công, chương trình giải mã chuỗi flag.

Cơ chế:

-   Dữ liệu được lưu dạng mã hóa.
-   Mỗi byte được XOR với key:

```{=html}
<!-- -->
```
    0x5A

Code giải mã tương đương:

``` python
flag = bytes(
    byte ^ 0x5A
    for byte in encrypted_data
)
```

Sau khi XOR:

    NNS{1_h0p3_y0u_p47ch3d_7h3_0pc0d3_dur1ng_run71m3_jnz_15_much_b3773r_7h4n_jz}

------------------------------------------------------------------------

# 6. Flag

    NNS{1_h0p3_y0u_p47ch3d_7h3_0pc0d3_dur1ng_run71m3_jnz_15_much_b3773r_7h4n_jz}

------------------------------------------------------------------------

# 7. Tổng kết kiến thức

Qua challenge này học được:

-   Cách debug chương trình Windows x64 bằng x64dbg.
-   Cách tìm đoạn code kiểm tra điều kiện.
-   Ý nghĩa của các conditional jump:

  Instruction   Ý nghĩa
  ------------- ----------------------
  JE/JZ         Jump if Equal / Zero
  JNE/JNZ       Jump if Not Equal
  JMP           Jump không điều kiện

-   Cách patch opcode trực tiếp trong debugger.
-   Cách bypass logic kiểm tra để lấy flag.

Đây là một bài reverse engineering cơ bản giúp làm quen với kỹ thuật
patch binary.
