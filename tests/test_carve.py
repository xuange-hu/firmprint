"""Stdlib carving: constant → peripheral, entropy and strings.

Carving is the engine that runs everywhere, so it is also the engine a reviewer
can most easily falsify.  The tests below pin three things people get wrong:
the *count* is exact while *evidence* is capped (a report that says "8
references" after printing 2 quotes is lying about its own output), pointers
into the image are excluded rather than counted as peripheral traffic, and a
memory window is never reported as a peripheral.
"""
from __future__ import annotations

import random
import struct

import pytest
from conftest import ihex

from firmprint import carve
from firmprint.container import Image, Segment, load
from firmprint.evidence import STRICT_CONFIDENCE, validate
from firmprint.socdb import load_soc


@pytest.fixture(scope="module")
def soc() -> carve.Soc:
    return load_soc("stm32f427xx")


def image_of(data: bytes, base: int = 0x0800_0000) -> Image:
    seg = Segment(base, data, "text", ".text", "raw", 0)
    return Image("t", len(data), "raw", "arm", "little", None, [seg])


def words(*values: int, pad_to: int | None = 64) -> bytes:
    body = struct.pack(f"<{len(values)}I", *values)
    if pad_to and len(body) < pad_to:
        body += b"\xff" * (pad_to - len(body))     # erased flash: even, so no fake table
    return body


# ------------------------------------------------------------------ constant carving

def test_a_block_address_carves_to_the_block_and_the_register_name(soc):
    g, u, r = (soc.peripherals[n]["base"] for n in ("GPIOA", "USART1", "RCC"))
    data = words(g, g + 0x00, u + 0x0C, r + 0x30)
    counts, hits, stats = carve.carve_bases(image_of(data), soc)

    assert counts == {("GPIOA", "MODER"): 2, ("USART1", "CR1"): 1, ("RCC", "AHB1ENR"): 1}
    assert stats["words_examined"] == len(data) // 4
    assert stats["candidate_words"] == 4
    # every quote carries the four bytes that produced it, at the right place
    ev = hits[("USART1", "CR1")][0]
    assert ev.kind == "word" and ev.file_offset == 8 and ev.vaddr == 0x0800_0008
    assert bytes.fromhex(ev.hex) == data[8:12] == struct.pack("<I", u + 0x0C)


def test_an_unmapped_constant_costs_a_prefix_check_and_nothing_else(soc):
    data = words(0xDEAD_BEEF, 0x0000_0001)
    counts, _hits, stats = carve.carve_bases(image_of(data), soc)
    assert counts == {}
    assert stats["candidate_words"] == 0
    assert stats["words_examined"] == len(data) // 4


def test_pointer_literals_into_the_image_are_dropped_not_counted_as_traffic(soc):
    """A literal pool full of code/RAM addresses would otherwise look like a device
    that touches FLASH and SRAM registers.  `exclude_ranges` is what stops that."""
    data = words(0x0800_0000, 0x2000_0000)
    keep, _h, stats = carve.carve_bases(image_of(data), soc)
    dropped, _h2, stats2 = carve.carve_bases(
        image_of(data), soc, exclude_ranges=[(0x0800_0000, 0x0800_1000), (0x2000_0000, 0x2002_0000)])

    assert set(keep) == {("FLASH", None), ("SRAM1", None)}
    assert dropped == {}
    assert stats["excluded_pointers"] == 0 and stats2["excluded_pointers"] == 2


def test_evidence_is_capped_but_the_count_stays_exact(soc):
    g = soc.peripherals["GPIOA"]["base"]
    counts, hits, _stats = carve.carve_bases(image_of(words(*[g] * 5, pad_to=None) ), soc, ev_cap=2)
    assert counts[("GPIOA", "MODER")] == 5
    assert len(hits[("GPIOA", "MODER")]) == 2

    usage = carve.peripheral_usage(counts, hits)
    assert usage["GPIOA"]["total"] == 5                     # summary says 5, quotes 2
    assert len(usage["GPIOA"]["evidence"]) == 2


def test_fold_keys_registerless_hits_on_the_block_base(soc):
    """A struct-less window has no register names, so its quotes must not invent any."""
    g = soc.peripherals["GPIOA"]["base"]
    counts, hits, _ = carve.carve_bases(image_of(words(0x2000_0000, g)), soc)
    usage = carve.peripheral_usage(counts, hits)
    assert usage["SRAM1"]["registers"] == {"(block base)": 1}
    assert usage["GPIOA"]["registers"] == {"MODER": 1}
    assert soc.register_name("GPIOA", 0) == "MODER"


# ---------------------------------------------------------------------- usage claims

def test_a_memory_window_is_reported_as_a_reference_not_a_peripheral(soc):
    counts, hits, _ = carve.carve_bases(image_of(words(0x2000_0000)), soc)
    f, = carve.usage_findings(carve.peripheral_usage(counts, hits), soc)
    assert f.kind == "memory.reference"
    assert f.rule == "memory.reference.carved-constants"
    assert "no CMSIS register struct" in f.summary
    assert f.confidence < STRICT_CONFIDENCE


def test_confidence_tracks_the_reference_count_and_never_outruns_it(soc):
    g = soc.peripherals["GPIOA"]["base"]
    ladder = []
    for n in (1, 3, 10):
        counts, hits, _ = carve.carve_bases(image_of(words(*[g] * n, pad_to=None)), soc)
        f, = carve.usage_findings(carve.peripheral_usage(counts, hits), soc)
        ladder.append((f.metrics["references"], f.confidence))
    assert ladder == [(1, 0.55), (3, 0.7), (10, 0.82)]


def test_carved_findings_satisfy_the_contract_on_their_own(soc):
    g, u = soc.peripherals["GPIOA"]["base"], soc.peripherals["USART1"]["base"]
    counts, hits, _ = carve.carve_bases(image_of(words(g, u + 0x0C, 0x2000_0000)), soc)
    findings = carve.usage_findings(carve.peripheral_usage(counts, hits), soc)
    assert len(findings) == 3
    assert not validate(findings), validate(findings)
    for f in findings:
        assert f.unknowns, "carving must state that a constant is not an access"
        assert any("capstone" in u for u in f.unknowns)


def test_findings_are_ordered_by_reference_count_then_reported(soc):
    g, u = soc.peripherals["GPIOA"]["base"], soc.peripherals["USART1"]["base"]
    counts, hits, _ = carve.carve_bases(image_of(words(*[u] * 4, g, g + 0x04)), soc)
    per = carve.peripheral_usage(counts, hits)
    names = [f.subject for f in carve.usage_findings(per, soc)]
    assert names[0] == "USART1"
    assert [f.metrics["references"] for f in carve.usage_findings(per, soc)] == [4, 2]


# ------------------------------------------------------------------------ entropy

def test_random_bytes_read_as_an_encrypted_candidate(soc):
    blob = random.Random(7).randbytes(0x2000)
    f = carve.entropy_finding(image_of(blob))
    assert f.kind == "region.entropy" and f.confidence == 0.6
    assert f.metrics["high_entropy_blocks"] == 2
    assert f.metrics["max_entropy"] > 7.9
    assert len(f.evidence) == 2                      # one region per hot block
    assert not validate([f])
    assert any("cannot distinguish" in u for u in f.unknowns)


def test_erased_flash_gets_a_low_confidence_claim_and_no_evidence_needed():
    f = carve.entropy_finding(image_of(bytes(0x1000)))
    assert f.confidence == 0.4 < STRICT_CONFIDENCE
    assert f.evidence == []
    assert f.metrics["max_entropy"] == 0.0           # never report -0.0 bits/byte
    assert "-0.00" not in f.summary
    assert not validate([f])


def test_a_short_trailing_chunk_is_not_scored():
    """Entropy over 200 bytes is noise; block sizes below 256 are skipped."""
    assert carve.entropy_regions(image_of(random.Random(1).randbytes(200))) == []
    assert carve.entropy_finding(image_of(bytes(100))) is None


# ------------------------------------------------------------------------- strings

def test_pathological_ascii_runs_are_rejected_and_a_source_name_is_kept():
    blob = (b"a" * 20 + b"\x00" + b"0" * 20 + b"\x00" + b"!" * 20 + b"\x00"
            + b"abcdefg" + b"\x00" + b"stm32f429_init.c" + b"\x00" * 8)
    f = carve.strings_finding(image_of(blob))
    assert f.metrics == {"count": 1, "informative_total": 1, "hint_count": 1}
    assert f.evidence[0].text == "stm32f429_init.c"
    assert f.confidence == 0.62


def test_a_run_below_minlen_is_dropped():
    assert carve.strings_finding(image_of(b"abcdefg\x00" * 4)) is None


def test_strings_without_an_identity_hint_stay_below_the_strict_bar():
    f = carve.strings_finding(image_of(b"AT command parser\x00"))
    assert f.confidence == 0.45 < STRICT_CONFIDENCE
    assert f.evidence[0].text == "AT command parser"


def test_the_limit_caps_kept_strings_and_says_so():
    blob = b"".join(f"module_name_{i:03d}.c\x00".encode() for i in range(50))
    f = carve.strings_finding(image_of(blob), limit=10)
    assert f.metrics["count"] == 10
    assert f.metrics["informative_total"] == 50, "the cap must not hide how many there were"
    assert len(f.evidence) <= 6


def test_packed_data_ascii_is_not_promoted_to_an_identity_hint():
    """Regression: a loose hint rule made JPEG-ish runs the report's 'strongest hints'."""
    junk = (b"@1Q`Qh`h\x00C,I)@%j*C\x00a@I+F2F F\x00@k@|@z@\x00" * 3)
    f = carve.strings_finding(image_of(junk))
    assert f.metrics["hint_count"] == 0
    assert f.confidence == 0.45 < STRICT_CONFIDENCE
    assert "no textual identity evidence" in f.summary
    assert not validate([f])


def test_a_build_string_past_the_sample_limit_is_still_found():
    """Regression: hints used to be searched only inside the first `limit` strings."""
    blob = b"".join(f"filler{i:04d}xxxxxxxx\x00".encode() for i in range(60))
    blob += b"driver_main.c\x00" + b"OPENMV2 with STM32F427\x00" + b"MicroPython 57a7b25003\x00"
    f = carve.strings_finding(image_of(blob), limit=10)
    assert f.metrics["hint_count"] == 3
    assert any("STM32F427" in e.text for e in f.evidence)
    assert "OPENMV2 with STM32F427" in f.summary, \
        "the part number must outrank a source path in the summary"
    assert f.evidence[0].vaddr is not None, "a hint the reader cannot locate is decoration"


def test_a_long_hint_is_cut_visibly_in_summary_and_exactly_in_evidence():
    """The summary quote is for reading; the evidence text is what a reader greps for.

    So the two get different treatment on purpose: an ellipsis in the summary, a byte-exact
    `text` plus a note that says the run is longer than what is shown.
    """
    text = "OPENMV2 firmware build banner for STM32F427 " * 4
    f = carve.strings_finding(image_of(text.encode() + b"\x00"))
    assert len(text) > 120
    assert f.evidence[0].text == text[:120], "evidence text must stay byte-exact"
    assert "ASCII run of 176 characters, first 120 shown" in f.evidence[0].note
    assert f"'{text[:59]}…'" in f.summary, f.summary


# ------------------------------------------------------- evidence anchors in text files

def test_a_word_found_in_intel_hex_anchors_to_the_record_not_a_linear_offset(tmp_path, soc):
    g = soc.peripherals["GPIOA"]["base"]
    path = tmp_path / "app.hex"
    path.write_bytes(ihex([(0x0800_0000, struct.pack("<I", g))]))
    image = load(str(path))
    counts, hits, _ = carve.carve_bases(image, soc)
    ev = hits[("GPIOA", "MODER")][0]

    assert ev.file_offset is not None
    text = path.read_bytes()
    assert text[ev.file_offset:ev.file_offset + 1] == b":", "anchor must be a record start"
    assert "; offset is the Intel HEX record holding these bytes" in ev.note
    assert struct.pack("<I", g).hex() in text[ev.file_offset:ev.file_offset + 32].decode()
