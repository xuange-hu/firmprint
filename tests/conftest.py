"""Shared fixtures: real samples when present, synthetic images always."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "openmv2"
ELF = SAMPLES / "firmware.elf"
BIN = SAMPLES / "firmware.bin"

# Tests must run from a fresh checkout, before anyone remembers to `pip install`.
# An installed package wins; this only adds the source tree when it is absent.
try:
    import firmprint  # noqa: F401
except ImportError:
    sys.path.insert(0, str(ROOT / "src"))


def pytest_configure(config):
    config.addinivalue_line("markers", "sample: needs samples/openmv2 (tools/get_sample.py)")


@pytest.fixture(scope="session")
def elf_path() -> Path:
    if not ELF.exists():
        pytest.skip("run: python tools/get_sample.py")
    return ELF


@pytest.fixture(scope="session")
def bin_path() -> Path:
    if not BIN.exists():
        pytest.skip("run: python tools/get_sample.py")
    return BIN


@pytest.fixture(scope="session")
def merged_path() -> Path:
    """The release image: a 64 KB bootloader followed by the application."""
    p = SAMPLES / "openmv.bin"
    if not p.exists():
        pytest.skip("run: python tools/get_sample.py")
    return p


#: second board, second family: OpenMV3 is an STM32F765 build, and its dump is the
#: case that made the F4-only ranking wrong (see docs/case-openmv3.md)
OMV3 = ROOT / "samples" / "openmv3"


@pytest.fixture(scope="session")
def omv3_bin_path() -> Path:
    p = OMV3 / "firmware.bin"
    if not p.exists():
        pytest.skip("run: python tools/get_sample.py --board OPENMV3")
    return p


@pytest.fixture(scope="session")
def omv3_elf_path() -> Path:
    p = OMV3 / "firmware.elf"
    if not p.exists():
        pytest.skip("run: python tools/get_sample.py --board OPENMV3")
    return p


def ihex(rows: list[tuple[int, bytes]], start_linear: int | None = None,
         chunk: int = 16) -> bytes:
    """Build a valid Intel HEX image (00 data, 04 extended-linear, 05 start, 01 EOF).

    Type-04 records are emitted whenever the upper 16 bits of the address change,
    so a Cortex-M image can be described at its real 0x0800_0000 link address
    instead of being folded into 16-bit offsets.
    """
    out: list[str] = []

    def rec(kind: int, addr: int, data: bytes) -> str:
        # ":LLAAAATT<data><crc>" — byte count first, then the 16-bit address field
        body = [len(data), (addr >> 8) & 0xFF, addr & 0xFF, kind, *data]
        return ":" + "".join(f"{b:02X}" for b in body) + f"{(-sum(body)) & 0xFF:02X}"

    if start_linear is not None:
        out.append(rec(5, 0, struct.pack(">I", start_linear)))
    cur_hi = None
    for addr, data in rows:
        pos, rest = addr, data
        while rest:
            hi = pos >> 16
            if hi != cur_hi:
                out.append(rec(4, 0, struct.pack(">H", hi)))
                cur_hi = hi
            take = min(chunk, len(rest), 0x10000 - (pos & 0xFFFF))
            out.append(rec(0, pos & 0xFFFF, rest[:take]))
            pos += take
            rest = rest[take:]
    out.append(":00000001FF")
    return ("\n".join(out) + "\n").encode()


def uf2(target_addr: int, payload: bytes, family: int | None = None,
        flags: int = 0) -> bytes:
    """Spec-shaped 512-byte UF2 blocks: header at 0/4/8/12/16/20/24/28, magicEnd at 508."""
    import math
    n = max(1, math.ceil(len(payload) / 476))
    out = bytearray()
    for i in range(n):
        part = payload[i * 476:(i + 1) * 476]
        f = flags | (0x2000 if family is not None else 0)
        b = bytearray(512)
        struct.pack_into("<IIIIIIII", b, 0, 0x0A324655, 0x9E5D5157, f,
                         target_addr + i * 476, len(part), i, n, family or 0)
        b[32:32 + len(part)] = part
        struct.pack_into("<I", b, 508, 0x0AB16F30)
        out += b
    return bytes(out)


def cortex_m_image(base: int = 0x0800_0000, n_vectors: int = 96,
                   ram: int = 0x2000_8000, code_bytes: int = 0x400) -> bytes:
    """A synthetic but spec-shaped flash image: table, handlers, then erased flash."""
    words = [ram - 0x20, base + 0x101]
    words += [base + 0x101 + i * 2 for i in range(2, n_vectors)]   # odd, ascending
    words += [0xFFFF_FFFE] * (code_bytes // 4)      # even: cannot fake a second table
    return struct.pack(f"<{len(words)}I", *words)


def dfuse_stub(tail_bytes: bytes = b"") -> bytes:
    """Enough of a ST DfuSe header for is_dfuse() to recognise the wrapper.

    Deliberately not a full container: firmprint detects DfuSe and refuses to guess
    its element offsets, so the only behaviour worth testing is the refusal.
    """
    wrapper = b"DfuSe" + bytes([1, 1]) + b"DfuTarg" + bytes([0])
    wrapper += struct.pack("<II", 11, 1) + bytes(3)     # 26 bytes of framing
    return wrapper + (tail_bytes or bytes(200))
