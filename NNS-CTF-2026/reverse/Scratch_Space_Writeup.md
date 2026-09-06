# CTF Writeup - Scratch Space

## Challenge Information

-   **Challenge:** Scratch Space
-   **Category:** Reverse Engineering
-   **Difficulty:** Beginner
-   **Author:** hoover

------------------------------------------------------------------------

# 1. Challenge Description

The binary asks the user to guess a passphrase. The passphrase is the
flag, but it is never stored directly on disk and is never passed to
library functions.

The program:

1.  Maps a temporary memory page using `mmap()`.
2.  Builds the real passphrase inside that memory.
3.  Compares the user's input using its own loop.
4.  Clears the memory.
5.  Unmaps the page.

Because of this:

-   `strings` does not reveal the flag.
-   `ltrace` shows nothing useful.
-   `strace` does not expose the secret.

The objective is to inspect runtime memory or reverse the generation
algorithm.

------------------------------------------------------------------------

# 2. Initial Analysis

Check the binary:

``` bash
file scratch-space
```

The program is an x86-64 ELF executable.

Using static analysis:

``` bash
objdump -d -M intel scratch-space
```

we can identify the important flow:

    mmap()
       |
    generate secret in memory
       |
    compare input
       |
    wipe memory
       |
    munmap()

The flag only exists for a short time during execution.

------------------------------------------------------------------------

# 3. Reverse Engineering the Generator

The important part of the disassembly is a pseudo-random generator:

``` c
seed = seed * 0x343fd + 0x269ec3;
```

The generated value is used to decode each byte:

``` c
flag_byte = encrypted_byte ^ ((seed >> 16) & 0xff);
```

The binary contains encrypted bytes instead of the real flag.

------------------------------------------------------------------------

# 4. Solving Script

``` python
blob = bytes.fromhex(
    "54 81 f7 8c 0b 8e 37 d2 "
    "13 52 ac b1 a9 4e c5 ba "
    "20 46 81 3a 17 10 49 bb "
    "f6 7c 7f 91 12 0c 3e 20 "
    "09 b8 c7 ab 8b f3 33 c7 "
    "53 e0"
)

seed = 0x311023df

flag = []

for b in blob:
    seed = (seed * 0x343fd + 0x269ec3) & 0xffffffff
    flag.append(b ^ ((seed >> 16) & 0xff))

print(bytes(flag).decode())
```

Running:

``` bash
python3 solve.py
```

returns:

    NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}

------------------------------------------------------------------------

# 5. Flag

    NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}

------------------------------------------------------------------------

# 6. Lessons Learned

This challenge demonstrates that sensitive data may not exist as static
strings inside a binary.

Important techniques:

-   Debugging with GDB/pwndbg.
-   Inspecting memory regions created by `mmap`.
-   Understanding runtime-generated secrets.
-   Reversing simple encoding algorithms.
-   Dumping data before memory wiping.

The key idea:

> A flag can exist only temporarily in memory. Static analysis is not
> always enough; runtime analysis is essential.
