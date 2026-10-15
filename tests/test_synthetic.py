"""`tools/make_synthetic.py` is what a stranger runs before they have downloaded anything.

It is not a test fixture, it is a promise in the README: `firmprint scan` must answer,
honestly and with zero contract violations, on a file that came from `pip install` plus
one script.  Two things have gone wrong here already, so both are pinned: the hand-written
Thumb encoding did not say what its comment claimed, and the image was described as
producing a row that it did not produce.
"""
from __future__ import annotations

import importlib.util
import struct

import pytest
from conftest import ROOT

from firmprint import cli, decode


def _load_script():
    """A checkout-only script: a wheel does not ship `tools/`."""
    script = ROOT / "tools" / "make_synthetic.py"
    if not script.exists():
        pytest.skip("the generator lives in the repository checkout")
    spec = importlib.util.spec_from_file_location("make_synthetic", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


needs_capstone = pytest.mark.skipif(not decode.available(), reason="capstone not installed")


# --------------------------------------------------------------------------- the shape

def test_the_image_is_shaped_like_cortex_m_firmware():
    gen = _load_script()
    data = gen.build()
    msp, reset = struct.unpack_from("<II", data, 0)
    assert (msp, reset) == (gen.MSP, gen.RESET)
    assert msp == 0x2001_0000 and reset & 1, "SP is even or the reset handler lost Thumb"
    # every handler must point back into this image: a table of garbage is not a table
    for off in range(0, 4 * gen.TABLE_SLOTS, 4):
        (word,) = struct.unpack_from("<I", data, off)
        assert off == 0 or gen.FLASH <= word < gen.FLASH + len(data) or word == 0


# ------------------------------------------------------------------- the machine code

@needs_capstone
def test_the_mov_pair_materialises_the_address_its_comment_claims():
    """The comments in the generator are only as good as the bytes next to them."""
    from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs

    gen = _load_script()
    data = gen.build()
    start = 0x1000                                     # body offset of the reset handler
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    ins = list(md.disasm(data[start:start + 12], gen.FLASH + start))
    got = [(i.mnemonic, i.op_str) for i in ins]
    assert [i.mnemonic for i in ins[:4]] == ["movw", "movt", "movs", "str"], got[:4]
    assert ins[0].op_str.startswith("r0,") and ins[1].op_str.startswith("r0,")
    lo, hi = (int(op.split("#", 1)[1], 0) for op in (ins[0].op_str, ins[1].op_str))
    assert (hi << 16) | lo == gen.GPIOA_MODER, f"the pair builds 0x{(hi << 16 | lo):08X}, not GPIOA+MODER"
    assert ins[3].op_str == "r1, [r0]", got[3]


@needs_capstone
def test_the_encoder_agrees_with_capstone_across_the_immediate_space():
    from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs

    gen = _load_script()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    imms = [0x0000, 0x0001, 0x0009, 0x000A, 0x00FF, 0x0100, 0x07FF, 0x0800, 0x4002, 0xC350,
            0xF800, 0xFFFE, 0xFFFF]
    imms += list(range(0, 0x10000, 383))
    for imm in imms:
        for upper, want in ((False, "movw"), (True, "movt")):
            ins = list(md.disasm(gen._movimm(3, imm, upper=upper), 0))
            assert len(ins) == 1 and ins[0].mnemonic == want, (hex(imm), want, ins)
            reg, _, printed = ins[0].op_str.partition(", #")
            assert reg == "r3" and int(printed, 0) == imm, (hex(imm), ins[0].op_str)


# ------------------------------------------------------------------- the report it gives

@needs_capstone
def test_the_strict_scan_of_the_synthetic_image_produces_rows(tmp_path, capsys):
    """'Every engine produces a row' is a claim about output, so it is tested as output."""
    gen = _load_script()
    blob = tmp_path / "blob.bin"
    blob.write_bytes(gen.build())
    assert cli.main(["scan", str(blob), "--strict"]) == 0
    out = capsys.readouterr().out
    assert "contract    0 violation(s)" in out
    kinds = {line.split()[0] for line in out.splitlines() if line and not line.startswith(" ")}
    assert {"peripheral.access", "peripheral.materialised", "cortex-m.vector_table"} <= kinds
    # one shared constant cannot separate three maps: the honest answer is `?`
    match = next(ln for ln in out.splitlines() if ln.startswith("match"))
    assert match.startswith("match       ?"), match


def test_the_dependency_free_path_still_answers(tmp_path, capsys):
    """On a box that refused to install capstone the stdlib engines must carry the report."""
    gen = _load_script()
    blob = tmp_path / "blob.bin"
    blob.write_bytes(gen.build())
    assert cli.main(["scan", str(blob), "--no-code", "--strict"]) == 0
    out = capsys.readouterr().out
    assert "contract    0 violation(s)" in out
    assert "cortex-m.vector_table" in out and "peripheral.usage" in out
