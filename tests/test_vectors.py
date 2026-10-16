"""Cortex-M vector-table shape detection and the base inference that depends on it.

The table is the strongest structure in a headerless image, so the tests below
are the difference between "a tool that finds the table" and "a tool that prints
an address and hopes".  Negative cases matter more than positive ones here: an
over-eager shape test invents tables in random data and then builds a whole
report on top of them.
"""
from __future__ import annotations

import random
import struct

from conftest import cortex_m_image

from firmprint.carve import explained_constants
from firmprint.container import Image, Segment, load, load_raw
from firmprint.evidence import STRICT_CONFIDENCE, validate
from firmprint.socdb import load_soc
from firmprint.vectors import (
    MAX_GAP,
    MIN_ALIGN,
    MIN_ENTRIES,
    RAMISH,
    _in_ranges,
    infer_load_base,
    rank_socs,
    scan_tables,
)


def tables_of(data: bytes, base: int = 0x0800_0000):
    """Scan one blob under an assumed origin, without any container metadata."""
    seg = Segment(base, data, "text", None, "raw", 0)
    image = Image("t", len(data), "raw", "arm", "little", None, [seg])
    return scan_tables(image)


# ---------------------------------------------------------------- positive shapes

def test_a_spec_shaped_table_is_found_and_earns_its_confidence():
    f = tables_of(cortex_m_image(base=0x0800_0000))[0]
    assert f.kind == "cortex-m.vector_table"
    assert f.subject == "table@0x08000000"
    assert f.metrics["n_live"] == 95              # 94 handlers + the reset vector
    assert f.metrics["msp"] == "0x20007FE0"
    assert f.metrics["reset"] == "0x08000101"
    assert 0.6 <= f.confidence <= 0.99
    assert not validate([f]), validate([f])
    assert f.evidence[0].hex == cortex_m_image(base=0x0800_0000)[:8].hex()


def test_a_table_shifted_by_one_alignment_unit_is_still_found():
    """VTOR relocation puts tables at flash offsets, not only at offset 0."""
    data = b"\xff" * MIN_ALIGN + cortex_m_image(base=0x0800_0000)
    f = tables_of(data)[0]
    assert f.metrics["table_vaddr"] == "0x08000080"
    assert f.evidence[0].file_offset == MIN_ALIGN


def test_aliased_unused_vectors_read_as_one_default_handler():
    words = [0x2000_1000] + [0x0800_0101] * 95
    data = struct.pack(f"<{len(words)}I", *words) + b"\xff" * 256
    f = tables_of(data)[0]
    assert f.metrics["unique_handlers"] == 1
    assert f.metrics["unused_style"] == "aliased to a default handler"


def test_zeroed_unused_vectors_are_tolerated():
    """Real STM32 images leave unused entries at 0x0000_0000; that is not corruption."""
    words = [0x2000_1000, 0x0800_0101] + [0x0800_0101 + i * 4 for i in range(2, 40)]
    words += [0] * 40
    words += [0x0800_0101 + i * 4 for i in range(40, 60)]
    data = struct.pack(f"<{len(words)}I", *words) + b"\xff" * 256
    f = tables_of(data)[0]
    assert f.metrics["zeroed_slots"] == MAX_GAP + 1      # the gap rule ends the scan here
    assert f.metrics["scan_stopped_early"] is True
    assert "lower bound" in f.summary, "a truncated count must not read as a total"



# ---------------------------------------------------------------- negative shapes

def test_random_data_produces_no_table():
    rnd = random.Random(20261014)
    data = struct.pack("<4000I", *[rnd.getrandbits(32) for _ in range(4000)])
    assert tables_of(data) == []


def test_an_unaligned_table_is_rejected():
    """ARMv7-M cannot have a vector table at a 4-byte offset: reporting one is a lie.

    The alignment filter is what stops the scanner from finding a "table" at every
    lucky word pair in a .rodata blob.
    """
    data = b"\x00\x00\x00\x00" + cortex_m_image(base=0x0800_0000)
    assert tables_of(data) == []


def test_a_ram_copy_of_a_table_is_not_reported_as_one():
    """Handlers that point outside the loaded image cannot be its own vectors."""
    words = [0x2000_1000] + [0x0800_0101 + i * 2 for i in range(1, 96)]
    data = struct.pack(f"<{len(words)}I", *words) + b"\xff" * 256
    assert tables_of(data, base=0x2000_0000) == []


def test_fewer_than_min_entries_live_handlers_is_data():
    words = [0x2000_1000, 0x0800_0101] + [0x0800_0101 + i for i in range(3, 12)]
    words += [0] * 400
    data = struct.pack(f"<{len(words)}I", *words)
    assert len(words) > MIN_ENTRIES
    assert tables_of(data) == []


# ------------------------------------------------------------------ base inference

def test_standalone_application_dump_infers_the_higher_origin():
    """A dump of an application linked above a bootloader fits *one* origin.

    With the flash span padded to 128 KB, base 0x0800_0000 also puts the handler
    targets inside the image, so a pure "count the tables" score used to call that a
    tie and break it by preferring the higher origin.  It is not a tie: at the low
    origin the image's reset vector sits 64 KB above its own table, which no real
    vector table does, so the origin is rejected on evidence instead of on a
    preference — and answering 0x0800_0000 would have relabelled an application as a
    bootloader and put every address in the report 64 KB out.
    """
    app = cortex_m_image(base=0x0801_0000)
    data = app + b"\xff" * (0x2_0000 - len(app))
    base, n_tables, first_off, counts = infer_load_base(data)
    assert base == 0x0801_0000
    assert n_tables == 1 and first_off == 0
    assert counts[0x0800_0000] == 0, "the low origin must be rejected, not outvoted"
    assert counts[0x0801_0000] == 1
    assert load_raw(data, "app.bin").segments[0].vaddr == 0x0801_0000


def test_merged_dump_picks_the_low_origin_and_finds_both_tables():
    bl = cortex_m_image(base=0x0800_0000)
    merged = bl + b"\xff" * (0x10000 - len(bl)) + cortex_m_image(base=0x0801_0000)
    base, n_tables, first_off, counts = infer_load_base(merged)
    assert base == 0x0800_0000, "only the low origin explains both tables"
    assert n_tables == 2
    assert first_off == 0
    assert counts[0x0801_0000] == 0, counts   # the high origin loses the bootloader


def test_a_dump_that_starts_at_zero_is_still_a_real_base():
    """nRF52 links at 0x0000_0000; refusing base 0 would reject the whole family."""
    base, n_tables, _off, counts = infer_load_base(cortex_m_image(base=0x0000_0000))
    assert (base, n_tables) == (0x0000_0000, 1)
    assert counts[0x0000_0000] == 1, "one table, not three readings of the same one"


# ------------------------------------------------------------- table-shape honesty

def test_a_constant_pool_does_not_become_several_tables():
    """A run of ascending odd addresses is *one* structure, not a table per 128 bytes.

    Every vendor RAM window admits some of the image's own handler values as a "stack
    pointer", so the same run validates at offset 0, 0x80 and 0x100.  Reporting three
    tables where the image has one is what makes a scanner look like a slot machine, so
    a candidate that starts inside the entries of a stronger one is dropped.
    """
    words = [0x2000_7FE0] + [0x0800_0101 + i * 2 for i in range(1, 200)]
    data = struct.pack(f"<{len(words)}I", *words)
    found = tables_of(data)
    assert len(found) == 1, [f.subject for f in found]
    assert found[0].metrics["table_vaddr"] == "0x08000000"


def test_a_second_table_outside_the_first_ones_entries_survives():
    """The nesting filter must not swallow the merged-image case it was written near."""
    one = cortex_m_image(base=0x0800_0000)
    two = cortex_m_image(base=0x0801_0000)
    data = one + b"\xff" * (0x1_0000 - len(one)) + two
    found = tables_of(data, base=0x0800_0000)
    assert [f.metrics["table_vaddr"] for f in found] == ["0x08000000", "0x08010000"]


def test_a_reset_handler_far_above_its_own_table_is_not_a_table():
    """Reading an app dump at the bootloader's origin is a rejection, not a tie.

    The vectors sit at the start of the image and the reset handler is the code that
    follows them, so a candidate whose reset is 128 KB above its own address is the same
    table seen from the wrong base.
    """
    words = [0x2000_7FE0, 0x0802_0101] + [0x0802_0101 + i * 2 for i in range(2, 60)]
    data = struct.pack(f"<{len(words)}I", *words) + b"\xff" * 0x100
    assert tables_of(data, base=0x0800_0000) == []
    assert len(tables_of(data, base=0x0802_0000)) == 1


def test_proposed_bases_reads_the_origin_out_of_the_dump(omv3_bin_path):
    """0x0802_0000 is not in the canonical list; the image itself has to say it.

    `omv3_bin_path` is OpenMV3's application-only flash contents: its first two words
    are the stack pointer and the reset handler, and the handler is what names the
    address the whole file was linked at.
    """
    from firmprint.vectors import proposed_bases
    data = omv3_bin_path.read_bytes()
    assert 0x0802_0000 in proposed_bases(data)
    base, n_tables, first_off, _counts = infer_load_base(data)
    assert base == 0x0802_0000, hex(base)
    assert (n_tables, first_off) == (1, 0)
    elf = load(omv3_bin_path.with_name("firmware.elf"))
    assert elf.segments[0].vaddr == base, "the ELF's own program header agrees"


def test_an_itcm_stack_pointer_counts_as_ram(omv3_bin_path):
    """STM32H7 boots with MSP in ITCM at 0x0000_4000; a 0x1000_0000-only filter loses it.

    This is why the bottom of the address map is a window: not because any small
    integer is a stack pointer, but because the 64 KB ITCM of a Cortex-M7 really is one.
    """
    sp = struct.unpack_from("<I", omv3_bin_path.read_bytes(), 0)[0]
    assert sp < 0x1000_0000, hex(sp)
    assert _in_ranges(sp, RAMISH)
    assert len(tables_of(omv3_bin_path.read_bytes(), base=0x0802_0000)) == 1


def test_no_table_means_no_guess():
    rnd = random.Random(7)
    data = struct.pack("<3000I", *[rnd.getrandbits(32) for _ in range(3000)])
    base, n_tables, _off, counts = infer_load_base(data)
    assert n_tables == 0
    assert all(v == 0 for v in counts.values())


def test_load_raw_states_the_inference_and_the_alternatives():
    bl = cortex_m_image(base=0x0800_0000)
    merged = bl + b"\xff" * (0x10000 - len(bl)) + cortex_m_image(base=0x0801_0000)
    img = load_raw(merged, "merged.bin")
    assert img.fmt == "raw"
    assert img.segments[0].vaddr == 0x0800_0000
    joined = " ".join(img.notes)
    assert "inferred" in joined and "origins tested" in joined, img.notes
    assert "every other tested origin produced no table" in joined, img.notes
    assert "more than one vector table" in joined


def test_load_raw_names_the_origins_that_also_gave_a_table(merged_path):
    """The rejected alternatives belong in the note, not in a log nobody reads.

    The OpenMV release image is a real merged dump: read at the application's own
    origin it still shows one table, so the chosen origin wins on the strength of its
    best table and the note has to name the alternative that was close.
    """
    img = load_raw(merged_path.read_bytes(), str(merged_path))
    joined = " ".join(img.notes)
    assert "origins that also produced tables" in joined, img.notes
    assert "0x08010000(1)" in joined, img.notes


# ---------------------------------------------------------------------- real images

def test_the_application_dump_recovers_its_true_link_address(bin_path):
    """firmware.bin is the ELF's flash contents without any metadata.

    Its real link address is 0x0801_0000 because a 64 KB bootloader owns the
    bottom of flash, and nothing in the file says so.
    """
    data = bin_path.read_bytes()
    base, n_tables, _off, _counts = infer_load_base(data)
    assert base == 0x0801_0000
    assert n_tables == 1


def test_the_merged_release_image_reports_two_tables(merged_path):
    img = load_raw(merged_path.read_bytes(), str(merged_path))
    subjects = sorted(f.subject for f in scan_tables(img))
    assert subjects == ["table@0x08000000", "table@0x08010000"], subjects
    for f in scan_tables(img):
        assert f.metrics["n_live"] > 60
    assert not validate(scan_tables(img))


def test_the_elf_uses_its_program_headers_not_a_guess(elf_path):
    from firmprint.container import load
    img = load(str(elf_path))
    f = max(scan_tables(img), key=lambda x: x.confidence)
    assert f.metrics["table_vaddr"] == "0x08010000"
    assert f.evidence[0].file_offset is not None


# ---------------------------------------------------------------- SoC ranking

def test_ranking_follows_the_map_that_has_the_exclusive_constants():
    """The winner must be the part whose *peripheral map* the words fit.

    This is the case that a naive "count how many addresses are known" score
    gets wrong: H7's map is a superset in raw block count, so without the
    exclusive-constant term it can beat the part the image was actually built for.
    """
    f4, h7 = load_soc("stm32f427xx"), load_soc("stm32h743xx")
    f4_only = sorted({e["base"] for k, e in f4.peripherals.items()
                      if k not in h7.peripherals or h7.peripherals[k]["base"] != e["base"]})
    assert len(f4_only) > 20, "the two parts must actually disagree somewhere"
    words = [w for base in f4_only[:40] for w in (base, base + 4)]
    body = struct.pack(f"<{len(words)}I", *words)
    data = cortex_m_image(base=0x0800_0000) + b"\xff" * (MIN_ALIGN - len(cortex_m_image(base=0x0800_0000)) % MIN_ALIGN) + body
    img = load_raw(data, "synth.bin")
    tables = scan_tables(img)
    exclude = [(s.vaddr, s.end) for s in img.segments]
    explained = {name: explained_constants(img, soc, exclude_ranges=exclude)
                 for name, soc in (("stm32f427xx", f4), ("stm32h743xx", h7))}
    ranked = rank_socs(img, {"stm32f427xx": f4, "stm32h743xx": h7}, tables[0], explained)
    assert ranked[0].subject == "stm32f427xx"
    assert (ranked[0].metrics["exclusive_constants"]
            > ranked[1].metrics["exclusive_constants"])
    assert ranked[0].metrics["blind_constants"] == 0, ranked[0].metrics
    assert not validate(ranked)


def test_a_map_that_explains_nothing_exclusively_is_not_named_as_a_match():
    """Overlapping maps must produce a tie, not a confident wrong part number.

    Two maps that see exactly the same constants cannot be separated by this
    image, so the report has to say "no installed map is distinctive here" even
    when the shared evidence is strong.
    """
    f4 = load_soc("stm32f427xx")
    bases = sorted({e["base"] for e in f4.peripherals.values()})[:60]
    body = struct.pack(f"<{len(bases)}I", *bases)
    data = (cortex_m_image(base=0x0800_0000)
            + b"\xff" * (-len(cortex_m_image(base=0x0800_0000)) % MIN_ALIGN) + body)
    img = load_raw(data, "tie.bin")
    tables = scan_tables(img)
    exclude = [(s.vaddr, s.end) for s in img.segments]
    twin = load_soc("stm32f427xx")          # identical map on purpose
    explained = {"stm32f427xx": explained_constants(img, f4, exclude_ranges=exclude),
                 "alias": explained_constants(img, twin, exclude_ranges=exclude)}
    ranked = rank_socs(img, {"stm32f427xx": f4, "alias": twin}, tables[0], explained)
    assert ranked, ranked
    for f in ranked:
        assert f.metrics["exclusive_constants"] == 0
        assert f.confidence < STRICT_CONFIDENCE, f.confidence
        assert "no installed map is distinctive" in f.summary


def test_a_ranking_shows_four_maps_and_names_the_ones_it_dropped():
    """Ranking is the one place the tool deliberately reports less than it scored.

    Six installed maps, four `soc.candidate` findings: a reader has no way to tell
    "these are the databases" from "these are the top four" unless the finding says
    so, and that confusion is exactly how a ranking turns into a part number.
    """
    f4 = load_soc("stm32f427xx")
    bases = sorted({e["base"] for e in f4.peripherals.values()})[:60]
    body = struct.pack(f"<{len(bases)}I", *bases)
    data = (cortex_m_image(base=0x0800_0000)
            + b"\xff" * (-len(cortex_m_image(base=0x0800_0000)) % MIN_ALIGN) + body)
    img = load_raw(data, "six-maps.bin")
    tables = scan_tables(img)
    exclude = [(s.vaddr, s.end) for s in img.segments]
    socs = {f"map{i}": load_soc("stm32f427xx") for i in range(6)}
    explained = {n: explained_constants(img, s, exclude_ranges=exclude)
                 for n, s in socs.items()}
    ranked = rank_socs(img, socs, tables[0], explained)
    assert len(ranked) == 4, [f.subject for f in ranked]
    assert any("2 installed map(s) scored against this image but are not reported"
               in u for u in ranked[0].unknowns), ranked[0].unknowns
    # the disclosure belongs to the headline candidate; a runner-up is already a
    # runner-up and must not imply it is the last row of the whole ranking
    assert not any("not reported" in u for u in ranked[1].unknowns)
