# NNS CTF --- small guy

**Category:** Reverse Engineering\
**Challenge:** `small guy`\
**Author:** 0xle\
**Points:** 96\
**Solves:** 73

> A small guy once told me something special. Life hasn't been the same
> ever since.

------------------------------------------------------------------------

## 1. Tổng quan

Challenge cung cấp một ELF 64-bit Linux đã bị strip. Chương trình nhận
một argument theo dạng:

``` text
NNS{...}
```

và in một trong hai kết quả:

``` text
Wrong.
```

hoặc:

``` text
Correct!
```

Điểm thú vị của bài không nằm ở một memory corruption bug thông thường.
Logic kiểm tra được giấu một phần trong **DWARF exception-unwinding
metadata của `.eh_frame`**.

Nói cách khác:

-   `.text` chứa phần dispatcher/VM;
-   `.rodata` chứa bảng opcode, bảng hằng số và ciphertext;
-   `.eh_frame` chứa các `DW_CFA_val_expression`;
-   các DWARF expression này làm thay đổi giá trị register khi C++
    exception được unwind;
-   exception được dùng như một cơ chế thực thi các phép toán của VM.

Đây chính là ý của tên bài: **small guy** và câu mô tả về việc một
"small guy" nói điều gì đó đặc biệt --- thứ "đặc biệt" ở đây là
exception unwinding.

------------------------------------------------------------------------

## 2. Kiểm tra binary

Binary là:

``` text
ELF 64-bit LSB executable, x86-64
dynamically linked
stripped
```

Các symbol quan trọng vẫn xuất hiện vì đây là các symbol của runtime:

``` text
__cxa_throw
__cxa_begin_catch
__cxa_allocate_exception
__gxx_personality_v0
_Unwind_Resume
strlen
memcmp
```

Sự xuất hiện đồng thời của:

``` text
__cxa_throw
__gxx_personality_v0
_Unwind_Resume
```

là dấu hiệu rất đáng chú ý đối với một bài reverse.

------------------------------------------------------------------------

## 3. Tìm hàm `main`

Vì binary bị strip, không còn tên `main`, nhưng entry point vẫn gọi:

``` asm
mov    rdi, 0x400450
call   __libc_start_main
```

Do đó `0x400450` chính là hàm main.

Phần đầu:

``` asm
400450:  push   rbx
400451:  cmp    edi, 0x2
400454:  jne    400499
400456:  mov    rbx, QWORD PTR [rsi+0x8]
40045a:  mov    rdi, rbx
40045d:  call   strlen
```

Chương trình yêu cầu đúng 2 argument (`argc == 2`) và lấy `argv[1]`.

------------------------------------------------------------------------

## 4. Kiểm tra format input

Sau `strlen`, chương trình kiểm tra độ dài và prefix:

``` asm
400462: cmp    rax, 0x5
400466: ...
400468: cmp    DWORD PTR [rbx], 0x7b534e4e
```

`0x7b534e4e` ở little-endian chính là:

``` text
NNS{
```

Sau đó kiểm tra byte cuối:

``` asm
400470: cmp    BYTE PTR [rbx+rax*1-0x1], 0x7d
```

tức là:

``` text
}
```

Nếu chưa đúng format, chương trình có nhánh đặc biệt:

``` asm
400501: add    rbx, 4
400505: sub    rax, 5
400509: jmp    40047b
```

Như vậy prefix/suffix được loại khỏi phần payload trước khi xử lý.

Cuối cùng chương trình yêu cầu payload có đúng:

``` text
0x20 = 32 bytes
```

Thông báo lỗi cũng xác nhận:

``` text
the small guy only understands 32 characters
```

Do đó format cuối cùng là:

``` text
NNS{<32 characters>}
```

------------------------------------------------------------------------

## 5. Nơi quan trọng nhất: `0x4004aa`

Nếu input hợp lệ, 32 byte được copy vào vùng global:

``` asm
4004aa: movdqu xmm0, XMMWORD PTR [rbx]
4004ae: movups XMMWORD PTR [rip+0xcfb4b], xmm0

4004b5: movdqu xmm0, XMMWORD PTR [rbx+0x10]
4004ba: movzx  eax, WORD PTR [rip+0xcfb3f]
4004c1: movups XMMWORD PTR [rip+0xcfb48], xmm0
4004c8: mov    QWORD PTR [rip+0xcfb51], rax
```

Vùng state bắt đầu tại:

``` text
0x4d0000
```

Đặc biệt:

``` asm
movzx eax, WORD PTR [0x4d0000]
mov   QWORD PTR [0x4d0020], rax
```

Như vậy **2 byte đầu của payload được copy thành seed/state**.

Sau đó:

``` asm
call 0x400600
```

và `0x400600` gọi:

``` asm
call 0x400618
```

------------------------------------------------------------------------

## 6. Hàm VM tại `0x400618`

Đây là dispatcher chính.

``` asm
400618: push   rbp
400619: mov    rbp, rsp
40061c: mov    rax, rdi
40061f: cmp    eax, 0x100
400624: je     400786
```

Register `rdi` là counter/index.

Điều kiện:

``` text
index == 0x100
```

nghĩa là VM chạy đúng:

``` text
0x100 = 256
```

iteration.

------------------------------------------------------------------------

## 7. Tính opcode

Mỗi iteration lấy một byte từ bảng tại:

``` text
0x4014d0
```

Code:

``` asm
40062a: movzx r8d, BYTE PTR [rax+0x4014d0]

400632: mov    rcx, rax
400635: and    ecx, 0x7

400638: mov    r10, QWORD PTR [0x4d0020]
40063f: shr    r10, cl

400642: add    r8d, r10d
400645: and    r8d, 0x1f
```

Có thể viết lại:

``` c
opcode = table[index];

shift = index & 7;
opcode += state >> shift;

opcode &= 0x1f;
```

Do:

``` text
0x1f = 31
```

nên opcode nằm trong:

``` text
0..31
```

Tức là có **32 VM operations**.

------------------------------------------------------------------------

## 8. Dispatcher 32 nhánh

Tiếp theo:

``` asm
400649: mov    r9, QWORD PTR [rax*8+0x4015d0]
400650: mov    r10, QWORD PTR [0x4d0020]

400658: movabs r11, 0x9e3779b97f4a7c15
400662: imul   r10, r11
400666: xor    r9, r10

400669: push   r9
40066b: push   r9

40066d: lea    rdi, [rax+1]

400671: jmp    QWORD PTR [r8*8+0x401df0]
```

Điều này cho thấy rõ đây là một VM:

``` text
opcode
  |
  v
0x401df0 + opcode * 8
  |
  +--> operation 0
  +--> operation 1
  +--> ...
  +--> operation 31
```

Có 32 jump target tương ứng 32 opcode.

------------------------------------------------------------------------

## 9. Điểm bất thường: các operation gần như không có code

Ví dụ:

``` asm
400679: call 400618
40067e: jmp  400791

400683: call 400618
400688: jmp  400791

40068d: call 400618
400692: jmp  400791
```

v.v.

Nhìn bằng disassembler thông thường thì các opcode chỉ có:

``` text
call VM
jmp epilogue
```

Không hề thấy phép:

``` text
add
xor
mul
rotate
...
```

Nhưng state của VM lại có các register:

``` text
rbx
rcx
r12
r13
r14
```

và mỗi opcode có một phép biến đổi khác nhau.

Đây là dấu hiệu cho thấy logic đã được giấu bên ngoài `.text`.

------------------------------------------------------------------------

# 10. `.eh_frame` chính là VM

Chạy:

``` bash
readelf --debug-dump=frames ./small-guy
```

sẽ thấy FDE lớn:

``` text
FDE cie=00000000
pc=0000000000400618..0000000000400793
```

Đây chính là vùng VM.

Điều đặc biệt là FDE chứa rất nhiều:

``` text
DW_CFA_val_expression
```

Ví dụ:

``` text
DW_CFA_val_expression:
    r3 (rbx)
    DW_OP_breg3 (rbx): 0
    DW_OP_constu: 11400714819323198485
    DW_OP_plus
```

Nó tương đương:

``` c
rbx = rbx + 11400714819323198485;
```

Một operation khác:

``` text
DW_CFA_val_expression:
    r12 (r12)
    DW_OP_breg12 (r12): 0
    DW_OP_constu: 2862933555777941757
    DW_OP_mul
```

tương đương:

``` c
r12 = r12 * 2862933555777941757;
```

Như vậy `.eh_frame` đang chứa **code của VM dưới dạng DWARF
expressions**.

------------------------------------------------------------------------

# 11. Các phép toán trong DWARF expression

Một số expression tiêu biểu:

### ADD

``` text
breg3(rbx)
constu C
plus
```

tương đương:

``` c
rbx += C;
```

### MUL

``` text
breg12(r12)
constu C
mul
```

tương đương:

``` c
r12 *= C;
```

### XOR

``` text
breg3(rbx)
breg2(rcx)
xor
```

tương đương:

``` c
rbx ^= rcx;
```

### ROTATE

Ví dụ expression:

``` text
breg14(r14)
breg12(r12)
dup
constu 53
shl
swap
constu 11
shr
or
xor
```

có thể nhìn theo dạng:

``` c
tmp = r12;
tmp = (tmp << 53) | (tmp >> 11);
r14 ^= tmp;
```

Các rotate khác dùng các cặp shift khác nhau.

------------------------------------------------------------------------

# 12. Một opcode còn có vòng lặp trong DWARF

Một expression đáng chú ý:

``` text
DW_OP_breg3 (rbx)
DW_OP_breg2 (rcx)
DW_OP_lit3
DW_OP_and
DW_OP_lit1
DW_OP_plus
DW_OP_swap
DW_OP_constu: 1812433253
DW_OP_mul
DW_OP_constu: 2567483615
DW_OP_plus
DW_OP_swap
DW_OP_lit1
DW_OP_minus
DW_OP_dup
DW_OP_bra: -22
DW_OP_drop
```

Đây là một loop được biểu diễn hoàn toàn bằng DWARF stack machine.

Điều này giải thích tại sao nếu chỉ reverse `.text` thì gần như không
thể thấy toàn bộ thuật toán.

------------------------------------------------------------------------

# 13. Tại sao `.eh_frame` lại được thực thi?

Phần exception của chương trình nằm ở:

``` asm
400600:
    sub rsp, 8
    xor edi, edi
    call 400618
    add rsp, 8
    ret
```

Khi VM đạt:

``` text
index == 0x100
```

nó chạy:

``` asm
400786:
    sub rsp, 0x10
    call 400422
```

`0x400422` thực hiện:

``` asm
mov    edi, 4
call   __cxa_allocate_exception

mov    edx, 0
mov    esi, 0x403dc8
mov    DWORD PTR [rax], 1
mov    rdi, rax

call   __cxa_throw
```

Tức là:

``` text
VM
 |
 +--> throw C++ exception
          |
          +--> libgcc unwinder
                   |
                   +--> đọc .eh_frame
                   |
                   +--> evaluate DW_CFA_val_expression
                   |
                   +--> khôi phục/evaluate register state
```

Do đó các DWARF expressions thực sự trở thành một phần của execution
path.

------------------------------------------------------------------------

# 14. Các register chính của VM

Nhìn FDE:

``` text
LOC           CFA      rcx   rbx   rbp   r12   r13   r14   ra
```

Có thể xem:

``` text
rcx = temporary / index-related state
rbx = VM state
r12 = VM state
r13 = VM state
r14 = VM state
```

Đặc biệt `rcx` được save tại:

``` text
cfa-24
```

còn các register khác được cập nhật bởi `DW_CFA_val_expression`.

Đây là cách tác giả biến register unwind state thành VM registers.

------------------------------------------------------------------------

# 15. Ciphertext / target nằm trong `.rodata`

Sau bảng opcode và một số dữ liệu, `.rodata` chứa một vùng dữ liệu có
entropy cao.

Bắt đầu khoảng:

``` text
0x4015d0
```

có bảng 64-bit được VM sử dụng:

``` asm
mov r9, QWORD PTR [rax*8+0x4015d0]
```

và vùng dữ liệu phía sau là các hằng số/ciphertext.

Trong khi reverse không nên cố đọc trực tiếp thành ASCII vì dữ liệu này
không phải plaintext.

Điểm quan trọng là:

``` text
0x4014d0  -> opcode table
0x4015d0  -> per-round constants
0x401df0  -> jump table
.eh_frame -> actual VM operations
```

------------------------------------------------------------------------

# 16. Kiểm tra cuối cùng

Sau khi VM hoàn thành 256 iteration, `0x400600` trở về và chương trình
thực hiện:

``` asm
4004d4: mov    edx, 0x20
4004d9: mov    esi, 0x401dd0
4004de: mov    edi, 0x404080
4004e3: call   memcmp
```

Tức là:

``` c
memcmp(result, 0x401dd0, 0x20);
```

So sánh đúng:

``` text
32 bytes
```

Nếu bằng nhau:

``` text
Correct!
```

ngược lại:

``` text
Wrong.
```

Vì vậy mục tiêu của chúng ta là tìm input 32-byte tạo ra đúng 32-byte
target tại `0x401dd0`.

------------------------------------------------------------------------

# 17. Cách solve

Có hai hướng.

## Hướng 1 --- emulate VM

Ta có thể:

1.  Parse `.rodata`.
2.  Lấy opcode table.
3.  Lấy jump table.
4.  Parse `.eh_frame`.
5.  Chuyển từng `DW_CFA_val_expression` thành Python operation.
6.  Implement DWARF stack operations:
    -   `breg`
    -   `constu`
    -   `plus`
    -   `mul`
    -   `xor`
    -   `shl`
    -   `shr`
    -   `or`
    -   `and`
    -   `dup`
    -   `swap`
    -   `bra`
    -   `drop`
7.  Emulate VM.
8.  Brute-force seed 16-bit.

Vì seed là:

``` text
2 bytes = 16 bits
```

nên chỉ có:

``` text
2^16 = 65536
```

khả năng.

Đây là không gian tìm kiếm rất nhỏ.

------------------------------------------------------------------------

# 18. Hướng 2 --- reverse VM

Một số operation là các phép toán modulo `2^64`:

``` c
x += C
x *= C
x ^= y
```

và rotate/xor.

Các phép toán này có thể reverse nếu biết trạng thái đích.

Đặc biệt:

``` text
uint64_t
```

nên mọi phép arithmetic được xét modulo:

``` text
2^64
```

Với multiplication, nếu hằng số là số lẻ thì nó có nghịch đảo modulo
`2^64`:

``` python
inv = pow(C, -1, 1 << 64)
```

Do đó có thể đi ngược VM thay vì chạy brute-force toàn bộ 32-byte input.

------------------------------------------------------------------------

# 19. Seed

Từ:

``` asm
movzx eax, WORD PTR [0x4d0000]
```

ta biết 2 byte đầu của payload được dùng trực tiếp làm seed.

Do đó solver có thể:

``` python
for seed in range(0x10000):
    state = seed
    ...
```

Sau khi tìm được seed phù hợp, hai byte đầu plaintext cũng được xác
định.

Các byte còn lại được khôi phục từ quá trình reverse/emulation.

------------------------------------------------------------------------

# 20. Kết quả

Payload 32-byte thu được là:

``` text
unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!
```

Kiểm tra độ dài:

``` text
len("unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!") == 32
```

Sau khi thêm wrapper:

``` text
NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}
```

Chạy:

``` bash
./small-guy 'NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}'
```

kết quả:

``` text
Correct!
```

------------------------------------------------------------------------

# 21. Flag

``` text
NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}
```

------------------------------------------------------------------------

# 22. Lessons learned

Bài này có một kỹ thuật reverse rất đáng chú ý.

### 1. Đừng chỉ nhìn `.text`

Nếu chỉ disassemble:

``` text
0x400618 - 0x400793
```

ta thấy chủ yếu là dispatcher và recursive calls.

Logic thật nằm trong:

``` text
.eh_frame
```

### 2. `__cxa_throw` + `__gxx_personality_v0` là red flag

Khi một crackme/reversing challenge có:

``` text
__cxa_throw
__gxx_personality_v0
_Unwind_Resume
```

thì nên kiểm tra:

``` bash
readelf --debug-dump=frames ./binary
```

### 3. DWARF không chỉ dành cho debugger

DWARF expressions có thể biểu diễn các phép tính khá phức tạp.

Ở challenge này chúng được tận dụng như một **instruction set cho VM**.

### 4. Exception unwinding có thể trở thành control-flow

Tác giả dùng:

``` text
throw
  ↓
unwinder
  ↓
.eh_frame
  ↓
DW_CFA_val_expression
  ↓
register transformation
```

để thực hiện phép tính.

### 5. Đừng nhầm đây là "bug" truyền thống

Không có buffer overflow hay use-after-free cần exploit.

"Điểm yếu" theo góc nhìn reverse là việc chương trình **ẩn thuật toán
trong metadata mà compiler/runtime vẫn phải sử dụng**.

------------------------------------------------------------------------

## TL;DR

``` text
main
 |
 +-- check NNS{...}
 |
 +-- require 32-byte payload
 |
 +-- copy payload -> 0x4d0000
 |
 +-- seed = first 2 bytes
 |
 +-- VM @ 0x400618
       |
       +-- 256 rounds
       +-- opcode = table[index] + (state >> (index & 7))
       +-- 32-way jump table
       +-- operations hidden in .eh_frame
       +-- DW_CFA_val_expression modifies registers
       |
       +-- throw exception
              |
              +-- DWARF unwinding executes VM state
 |
 +-- memcmp(result, target, 32)
 |
 +-- Correct!
```

**Final flag:**

``` text
NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}
```
