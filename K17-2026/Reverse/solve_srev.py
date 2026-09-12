#!/usr/bin/env python3
"""Solve the supplied K17 CTF srev ELF using Python's standard library.

Usage:
    python3 solve_srev.py ./srev
    python3 solve_srev.py ./srev --verify-native

Native verification executes a temporary copy of the challenge on Linux.
Only the twelve initial candidate registers are patched; the input file is
never modified. The transformation, checks, and flag printer stay intact.
"""

import argparse
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


MASK = (1 << 64) - 1
REG_TABLE = 0x2060
HEADER = 0x20E0
TEMPLATES = 0x20F8
TEMPLATE_SIZE = 0xFC
CONTEXT_SIZE = 0xF8
PROGRAM = 0x3994


def load_program(blob):
    if blob[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected the supplied little-endian ELF64 srev file")
    if len(blob) < PROGRAM + 291 * CONTEXT_SIZE:
        raise ValueError("File is too short")
    magic, version, nt, ni = struct.unpack_from("<4sIII", blob, HEADER)
    if (magic, version, nt, ni) != (b"SREV", 0x100, 25, 291):
        raise ValueError("This solver targets the supplied 25-template, 291-instruction srev")
    offsets = struct.unpack_from("<16Q", blob, REG_TABLE)
    program = []
    for pc in range(ni):
        base = PROGRAM + pc * CONTEXT_SIZE
        argument = struct.unpack_from("<Q", blob, base + 0x90)[0]
        opcode = struct.unpack_from("<Q", blob, base + 0xA8)[0]
        program.append((opcode, argument))
    return offsets, program


def transform(registers, instructions, inverse=False):
    r = list(registers)
    ordered = reversed(instructions) if inverse else instructions
    for opcode, argument in ordered:
        dst = argument & 15
        immediate = bool(argument & 16)
        src = (argument >> 8) & 15
        if not 1 <= dst <= 12:
            raise ValueError("Unexpected destination in the candidate transform")
        if not immediate and (not 1 <= src <= 12 or src == dst):
            raise ValueError("Unexpected/non-invertible register operation")
        operand = argument >> 8 if immediate else r[src]
        if opcode == 5:  # ADD, inverse SUB
            r[dst] += -operand if inverse else operand
        elif opcode == 6:  # SUB, inverse ADD
            r[dst] += operand if inverse else -operand
        elif opcode == 7:  # XOR is its own inverse
            r[dst] ^= operand
        elif opcode == 8:  # ROR; a negative count produces ROL
            count = (-operand if inverse else operand) & 63
            r[dst] = (r[dst] >> count) | (r[dst] << ((-count) & 63))
        else:
            raise ValueError(f"Unexpected transform opcode {opcode}")
        r[dst] &= MASK
    return r


def solve(blob):
    offsets, program = load_program(blob)
    # At PCs 238..249, each nonzero result triggers the failure branch.
    for reg, pc in enumerate(range(238, 250), 1):
        opcode, argument = program[pc]
        if (opcode != 2 or (argument >> 24) & 15 != 2
                or (argument >> 28) & 15 != reg or argument >> 32 != 0):
            raise ValueError("Unexpected final comparison")
    # Reverse every operation, including the twelve target subtractions.
    arithmetic = program[2:238]
    initial = transform([0] * 16, arithmetic, inverse=True)
    if not all(32 <= c <= 126 for c in initial[1:13]):
        raise ValueError("Recovered candidate is not twelve printable characters")
    forward = transform(initial, arithmetic)
    if forward != [0] * 16:
        raise ValueError("Forward verification failed")
    body = bytes(initial[1:13])
    return body, offsets


def verify_native(blob, body, offsets):
    if not sys.platform.startswith("linux"):
        raise RuntimeError("Native verification requires Linux x86-64")
    patched = bytearray(blob)
    for reg, value in enumerate(body, 1):
        struct.pack_into("<Q", patched, TEMPLATES + 4 + offsets[reg], value)
    expected = b"K17{" + body + b"}\n"
    with tempfile.TemporaryDirectory(prefix="srev-check-") as directory:
        executable = Path(directory) / "srev-verified"
        executable.write_bytes(patched)
        executable.chmod(0o700)
        result = subprocess.run([str(executable)], capture_output=True, timeout=5)
    if result.returncode != 0 or result.stdout != expected:
        raise RuntimeError(
            f"Native verification failed: rc={result.returncode}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}")
    print("[+] Native copy: exit 0, exact flag output")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="srev", type=Path)
    parser.add_argument("--verify-native", action="store_true")
    args = parser.parse_args()
    blob = args.binary.read_bytes()
    body, offsets = solve(blob)
    print("[+] Reversed 236 arithmetic instructions")
    print("[+] Forward check: all 12 result registers are zero")
    if args.verify_native:
        verify_native(blob, body, offsets)
    print("K17{" + body.decode("ascii") + "}")


if __name__ == "__main__":
    main()
