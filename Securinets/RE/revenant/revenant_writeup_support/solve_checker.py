#!/usr/bin/env python3
"""Invert the observed Revenant checker using state and a baseline probe."""
import sys
from pathlib import Path

def rol8(v, n): return ((v << n) | (v >> (8-n))) & 255
def ror8(v, n): return ((v >> n) | (v << (8-n))) & 255

def main(state_path, probe_path):
    state = Path(state_path).read_bytes()
    zero_output = Path(probe_path).read_bytes()
    target = state[0x20:0x20+76]
    sbox = state[0x140:0x140+256]
    assert len(zero_output) == len(target) == 76
    assert len(sbox) == len(set(sbox)) == 256
    inverse = {v: i for i, v in enumerate(sbox)}
    masks = []
    result = bytearray(76)
    for i in range(76):
        j = 75-i
        rot = j % 7 + 1
        mask = zero_output[j] ^ rol8(sbox[ord('0')], rot)
        sboxed = ror8(target[j] ^ mask, rot)
        result[i] = inverse[sboxed]
        masks.append((j, mask))

    # Independent forward check (byte-for-byte, no external service).
    mask_by_j = dict(masks)
    actual = bytes(rol8(sbox[result[75-j]], (j % 7)+1) ^ mask_by_j[j] for j in range(76))
    assert actual == target, 'forward result differs from 76-byte target'
    flag = result.decode('ascii')
    assert flag.startswith('Securinets{') and flag.endswith('}')
    print('Flag:', flag)
    print(f'Length: {len(result)} bytes | S-box: {len(set(sbox))} unique values')
    print('Forward verification: 76/76 bytes match')
    print('target:', target.hex())

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('usage: python3 solve_checker.py constructor_state.bin baseline_zeros.bin')
    main(*sys.argv[1:])
