#!/usr/bin/env python3
"""Static extractor for Revenant's outer ELF; never executes the challenge."""
import hashlib
import struct
import sys
from pathlib import Path

U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF

def rolling_hash(data: bytes) -> int:
    state = 0
    for byte in data[:256]:
        state = (((state >> 1) | (state << 63)) & U64) ^ byte
        state = (state + 0xBF58476D1CE4E5B9) & U64
    return state

def xtea(v0: int, v1: int, k: tuple[int, ...]) -> bytes:
    total = 0
    for _ in range(32):
        mix = (((v1 << 4) ^ (v1 >> 5)) + v1) & U32
        v0 = (v0 + (mix ^ ((total + k[total & 3]) & U32))) & U32
        total = (total + 0x9E3779B9) & U32
        mix = (((v0 << 4) ^ (v0 >> 5)) + v0) & U32
        v1 = (v1 + (mix ^ ((total + k[(total >> 11) & 3]) & U32))) & U32
    return struct.pack('<II', v0, v1)

def main(challenge_path: str, data_path: str, out_path: str) -> None:
    challenge = Path(challenge_path).read_bytes()
    data = Path(data_path).read_bytes()
    assert challenge[:4] == b'\x7fELF'
    assert len(data) == 1028
    hostname = bytes(byte ^ 0x5A for byte in challenge[0x5678:0x5680])
    assert hostname == b'blackkad', f'wrong decoded hostname: {hostname!r}'
    h = struct.pack('<Q', rolling_hash(data))
    build8 = challenge[0x5694:0x569c]
    part2 = bytes(a ^ b for a, b in zip(h, build8))
    seed = hostname + part2 + data[0xA0:0xB0]
    digest = hashlib.sha256(seed).digest()
    words = struct.unpack('<8I', digest)
    size = struct.unpack_from('<Q', challenge, len(challenge)-8)[0]
    ciphertext = challenge[-8-size:-8]
    assert len(ciphertext) == size and size % 8 == 0

    plain = bytearray(size)
    for block in range(size // 8):
        stream = xtea((words[4]+block) & U32, words[5], words[:4])
        off = block * 8
        for j in range(8):
            plain[off+j] = ciphertext[off+j] ^ stream[j]
    assert plain.startswith(b'\x7fELF\x02\x01\x01\x00'), 'incorrect key or bad payload'
    Path(out_path).write_bytes(plain)
    print('hostname:', hostname.decode())
    print('sha256(seed):', digest.hex())
    print(f'cipher offset: 0x{len(challenge)-8-size:x}, payload bytes: {size}')
    print('decrypted magic:', plain[:16].hex(' '))
    print('inner sha256:', hashlib.sha256(plain).hexdigest())
    print('wrote:', out_path)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit('usage: python3 extract_inner.py challenge data.bin inner.elf')
    main(*sys.argv[1:])
