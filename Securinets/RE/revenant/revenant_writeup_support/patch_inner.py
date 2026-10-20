#!/usr/bin/env python3
"""Create temporary instrumented copies. Do not execute outside isolated CTF VM.

File offsets coincide with virtual addresses - 0x400000 for this inner ELF.
Use commands documented in the write-up for obtaining probe/table outputs.
"""
import sys
from pathlib import Path

# write(1, address 0x4c3d00, 8192); exit(0), placed at main.
DUMP_STATE = bytes.fromhex(
    'b801000000 bf01000000 be003d4c00 ba00200000 0f05 '
    'b83c000000 31ff 0f05'
)
# write(1, rsp+0x120, 76); exit(0), just before memcmp.
DUMP_TRANSFORM = bytes.fromhex(
    '488db42420010000 b801000000 bf01000000 '
    'ba4c000000 0f05 b83c000000 31ff 0f05'
)

def main(p):
    base = Path(p).read_bytes()
    assert base[:4] == b'\x7fELF'
    table_copy = bytearray(base)
    table_copy[0x4050:0x4050+len(DUMP_STATE)] = DUMP_STATE
    out1 = Path('dump_state.elf')
    out1.write_bytes(table_copy)
    out1.chmod(0o755)

    checker_copy = bytearray(base)
    checker_copy[0x4060:0x4066] = b'\x90' * 6  # skip environment-triggered branch
    checker_copy[0x39e0:0x39e0+len(DUMP_TRANSFORM)] = DUMP_TRANSFORM
    out2 = Path('dump_transform.elf')
    out2.write_bytes(checker_copy)
    out2.chmod(0o755)

    verify_copy = bytearray(base)
    verify_copy[0x4060:0x4066] = b'\x90' * 6  # do not change checker
    out3 = Path('verify.elf')
    out3.write_bytes(verify_copy)
    out3.chmod(0o755)

    print('Created:', out1, out2, out3)
    print('For isolated VM only. No file was executed.')

if __name__ == '__main__':
    if len(sys.argv) != 2: sys.exit('usage: python3 patch_inner.py inner.elf')
    main(sys.argv[1])
