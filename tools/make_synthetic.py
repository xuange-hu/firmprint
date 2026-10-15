#!/usr/bin/env python3
"""Write a small, honest Cortex-M image so the tool can be tried without a download.

The samples in `samples/` are the ones the verification documents are built from; this
script exists for the two cases where they are not available:

  * a fresh clone, before `python tools/get_sample.py` has been run;
  * CI, where a pass must not depend on a third-party release asset being reachable.

The image is synthetic but *shaped* like a real one: a vector table whose handlers all
point into flash, a stack pointer inside an F4 SRAM window, one device constant sitting
in a literal pool (what the stdlib carve engine sees), and a MOVW/MOVT pair that
materialises the same address into `r0` before storing through it (what capstone sees).
That is enough for every engine to produce a row -- `tests/test_synthetic.py` asserts the
kinds rather than trusting this sentence -- and it is also enough to show what the tool
does when the evidence is thin: with one peripheral constant present, all three installed
maps explain it, so the honest answer is `?` plus "no installed map is distinctive here":

    $ python tools/make_synthetic.py /tmp/blob.bin
    $ firmprint scan /tmp/blob.bin --strict
    match       ? stm32f427xx (f4, cortex-m4)  conf 0.58  no installed map is distinctive here

It is deliberately *not* a test fixture: `tests/` builds its own images so that a change
here cannot silently move 200 assertions.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

FLASH = 0x0800_0000
MSP = 0x2001_0000                 # inside STM32F427 SRAM1
RESET = FLASH + 0x101             # Thumb bit set, as a real table would
GPIOA_MODER = 0x4002_0000         # the one peripheral constant this image carries
TABLE_SLOTS = 48


def _movimm(rd: int, imm16: int, *, upper: bool) -> bytes:
    """Encode A32 `movw`/`movt r<rd>, #imm16` (T2) big-endian-free, little-endian.

    Written out rather than typed as magic bytes so the image cannot silently drift
    away from what the comment next to it claims.  The layout is ARMv7-M MOV (T4),
    where imm32 = imm4:i:imm3:imm8 and the two families differ by one bit:

        first halfword  =  0xF240 (movw) / 0xF2C0 (movt)  |  imm4  |  i << 10
        second halfword =  (imm3 << 12)  |  (Rd << 8)  |  imm8

    `tests/test_synthetic.py` checks every encoding against capstone, because the two
    hand-written guesses this replaced decoded as `mov r0, #0x200` and `eors r0, r4, #2`
    -- a synthetic image that disassembles to something else is worse than no image.
    """
    first = (0xF2C0 if upper else 0xF240) | ((imm16 >> 12) & 0xF) | (((imm16 >> 11) & 1) << 10)
    second = (((imm16 >> 8) & 7) << 12) | (rd << 8) | (imm16 & 0xFF)
    return struct.pack("<HH", first, second)


def _movw(rd: int, lo: int) -> bytes:
    return _movimm(rd, lo, upper=False)


def _movt(rd: int, hi: int) -> bytes:
    return _movimm(rd, hi, upper=True)


def build() -> bytes:
    table = struct.pack("<II", MSP, RESET)
    table += struct.pack("<I", RESET) * (TABLE_SLOTS - 2)
    assert len(table) == 4 * TABLE_SLOTS

    code = bytearray()
    # the reset handler: materialise GPIOA+MODER with MOVW/MOVT, then store through it
    code += _movw(0, GPIOA_MODER & 0xFFFF)             # movw r0, #0
    code += _movt(0, GPIOA_MODER >> 16)                # movt r0, #0x4002
    code += bytes([0x01, 0x21])                        # movs r1, #1
    code += bytes([0x01, 0x60])                        # str r1, [r0, #0]
    code += bytes([0x00, 0xBF])                        # nop
    while len(code) < 0x40:
        code += bytes([0x00, 0xBF])
    # a literal pool holding the same base: what the stdlib carve engine sees
    pool = struct.pack("<I", GPIOA_MODER)

    body = bytearray(0x2000)
    body[0:0 + len(code)] = code
    body[0x200:0x204] = pool
    return bytes(table) + bytes(0x1000 - len(table)) + bytes(body)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out", nargs="?", default="blob.bin", type=Path,
                    help="where to write the image (default: ./blob.bin)")
    ap.add_argument("--print-summary", action="store_true",
                    help="describe the image instead of only writing it")
    a = ap.parse_args()

    data = build()
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_bytes(data)
    print(f"wrote {a.out}: {len(data)} bytes, table of {TABLE_SLOTS} slots at 0x{FLASH:08X}")
    if a.print_summary:
        print(f"  MSP 0x{MSP:08X} (F427 SRAM1), reset 0x{RESET:08X} (Thumb)")
        print(f"  one device constant: 0x{GPIOA_MODER:08X} (GPIOA+MODER) in a literal pool")
        print("  expected: every installed map explains it, so the report must say `?`")
    print(f"next: firmprint scan {a.out} --strict")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
