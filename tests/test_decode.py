"""The optional capstone engine.

Two kinds of test live here.  The first feeds `decode` synthetic *instruction
streams* — named tuples that look exactly like capstone's output — so the
register-tracking rules can be pinned without an assembler and without a
disassembler version dependency.  The second runs the real thing over the sample
ELF and checks that every quoted byte is actually at the offset it claims, which
is the one property that makes the report re-checkable by a stranger.

Everything is skipped when capstone is not installed; the tool's contract is
that it degrades to carving and says so, and `test_without_capstone_...` checks
the degradation itself.
"""
from __future__ import annotations

import struct
from collections import Counter, defaultdict
from types import SimpleNamespace

import pytest

from firmprint import decode
from firmprint.container import Image, Segment, load
from firmprint.evidence import Evidence, validate
from firmprint.socdb import load_soc

pytestmark = pytest.mark.skipif(not decode.available(), reason="capstone not installed")

TEXT_BASE = 0x0800_1000
USART1 = 0x4001_1000
GPIOA = 0x4002_0000


@pytest.fixture(scope="module")
def soc():
    return load_soc("stm32f427xx")


@pytest.fixture
def image() -> Image:
    """A code segment whose bytes are irrelevant; the tests name instructions."""
    seg = Segment(TEXT_BASE, bytes(0x400), "text", ".text", "raw", 0)
    img = Image("t", 0x400, "raw", "arm", "little", None, [seg])
    img.symbols = {TEXT_BASE: "ll_uart_init", TEXT_BASE + 0x40: "dma_start"}
    return img


def insn(addr: int, mn: str, ops: str, raw: bytes = b"\x00\x68") -> SimpleNamespace:
    return SimpleNamespace(address=addr | 1, mnemonic=mn, op_str=ops, bytes=raw)


def sweep(insns, soc, image, stats=None):
    """Replay an instruction stream through the tracker exactly as _walk does."""
    state: dict[int, tuple[int, bool]] = {}
    accesses: dict = defaultdict(list)
    immediates: dict = defaultdict(list)
    stats = stats or {"engine": "capstone/test", "instructions": len(insns), "bytes_decoded": 0,
                      "coverage": 1.0, "memory_hits": 0}
    for i in insns:
        decode._step(i, soc, image, state, accesses, immediates, stats)
    return accesses, immediates, stats


# ------------------------------------------------------------------ the tracking rules

def test_the_engine_label_names_the_installed_distribution_not_the_lagging_module():
    """The label is provenance, so it must be a number `pip show` agrees with.

    capstone ships `__version__` = "5.0.7" inside the 5.0.9 wheel; a finding that cites
    "the disassembler said so" while naming a version nobody installed is the kind of
    loose provenance this project exists to avoid.
    """
    from importlib.metadata import version

    assert decode.engine_label() == f"capstone/{version('capstone')}"


def test_a_movw_movt_pair_then_a_store_becomes_a_write_to_the_named_register(soc, image):
    a, i, _ = sweep([insn(TEXT_BASE, "movw", f"r3, #0x{USART1 & 0xFFFF:04X}"),
                     insn(TEXT_BASE + 2, "movt", f"r3, #0x{USART1 >> 16:04X}"),
                     insn(TEXT_BASE + 4, "str", "r2, [r3, #0xc]")], soc, image)
    assert list(a) == [("USART1", "CR1", "write")]
    ev = a[("USART1", "CR1", "write")][0]
    assert ev.kind == "instruction" and ev.vaddr == TEXT_BASE + 4
    assert ev.file_offset == 4 and ev.hex == "0068"
    assert "str r2, [r3, #0xc]  [write]  in ll_uart_init" in ev.note


def test_a_load_through_a_tracked_base_is_reported_as_a_read(soc, image):  # noqa: E999
    a, _i, _ = sweep([insn(TEXT_BASE, "movw", "r3, #0x1000"),
                      insn(TEXT_BASE + 2, "movt", "r3, #0x4001"),
                      insn(TEXT_BASE + 4, "ldr", "r0, [r3]")], soc, image)
    assert list(a) == [("USART1", "SR", "read")]


def test_a_half_built_address_is_not_reported_as_an_access(soc, image):
    """MOVW alone gives only the low 16 bits.  Guessing the rest is how a tool
    turns 0x1000 into 'USART1 was touched'."""
    a, i, _ = sweep([insn(TEXT_BASE, "movw", "r3, #0x1000"),
                     insn(TEXT_BASE + 2, "str", "r2, [r3, #0xc]")], soc, image)
    assert a == {} and i == {}


def test_a_full_mov_immediate_is_tracked_and_materialises_the_block(soc, image):
    a, i, _ = sweep([insn(TEXT_BASE, "mov", f"r3, #0x{GPIOA:X}"),
                     insn(TEXT_BASE + 2, "ldr", "r1, [r3, #4]")], soc, image)
    assert list(a) == [("GPIOA", "OTYPER", "read")]
    assert [k[0] for k in i] == ["GPIOA"]


def test_add_on_a_tracked_base_keeps_tracking(soc, image):
    a, _i, _ = sweep([insn(TEXT_BASE, "mov", f"r3, #0x{USART1:X}"),
                      insn(TEXT_BASE + 2, "add", "r1, r3, #0x10"),
                      insn(TEXT_BASE + 4, "ldr", "r0, [r1]")], soc, image)
    assert list(a) == [("USART1", "CR2", "read")]


def test_a_pc_relative_literal_load_resolves_against_the_image(soc, image):
    """`ldr r3, [pc, #off]` is how compilers actually park peripheral bases.  The
    offset counts from (address + 4) aligned down to 4, so the test places the
    word where the ARM says it must be and nowhere else."""
    here = TEXT_BASE + 0x10
    lit = ((here + 4) & ~3) + 0x18
    seg = image.segments[0]
    seg.data = seg.data[:lit - TEXT_BASE] + struct.pack("<I", USART1 + 0x0C) + \
        seg.data[lit - TEXT_BASE + 4:]
    a, i, _ = sweep([insn(here, "ldr", "r3, [pc, #0x18]"),
                     insn(here + 2, "str", "r2, [r3]")], soc, image)
    assert list(i) == [("USART1", "CR1", None)]
    assert list(a) == [("USART1", "CR1", "write")]
    assert "0x4001100C" in i[("USART1", "CR1", None)][0].note


def test_a_call_or_push_clears_the_tracker_instead_of_inheriting_a_stale_base(soc, image):
    base = [insn(TEXT_BASE, "mov", f"r3, #0x{USART1:X}")]
    for stop in ("bl", "bx", "push", "cbz"):
        a, _i, _ = sweep(base + [insn(TEXT_BASE + 4, stop, "r0"),
                                 insn(TEXT_BASE + 6, "str", "r2, [r3]")], soc, image)
        assert a == {}, f"{stop} must reset tracked registers"


def test_it_block_does_not_end_the_sequence(soc, image):
    """`it e` + `strne` — clearing at the `it` is conservative but the store after
    it must still be seen, otherwise conditional register writes vanish."""
    a, _i, _ = sweep([insn(TEXT_BASE, "mov", f"r3, #0x{USART1:X}"),
                      insn(TEXT_BASE + 2, "it", "ne"),
                      insn(TEXT_BASE + 4, "strne", "r2, [r3, #0x10]")], soc, image)
    assert list(a) == [("USART1", "CR2", "write")]


def test_a_ram_window_is_counted_as_a_memory_hit_not_a_peripheral(soc, image):
    _a, _i, stats = sweep([insn(TEXT_BASE, "mov", "r3, #0x20000000"),
                           insn(TEXT_BASE + 2, "str", "r2, [r3]")], soc, image,
                          stats={"engine": "capstone/test", "instructions": 2,
                                 "bytes_decoded": 0, "coverage": 1.0})
    # both sites count: the MOVW/MOVT pair and the store through it
    assert _a == {} and stats["memory_hits"] == 2


def test_an_address_outside_the_map_produces_nothing(soc, image):
    a, i, _ = sweep([insn(TEXT_BASE, "mov", "r3, #0xd0000000"),
                     insn(TEXT_BASE + 2, "str", "r2, [r3]")], soc, image)
    assert a == {} and i == {}


def test_evidence_per_site_is_capped_while_the_engine_keeps_counting(soc, image):
    body = [insn(TEXT_BASE, "mov", f"r3, #0x{USART1:X}")]
    body += [insn(TEXT_BASE + 2 + 2 * k, "str", "r2, [r3]") for k in range(30)]
    a, _i, _ = sweep(body, soc, image)
    assert len(a[("USART1", "SR", "write")]) == 24          # 0x40011000 is USART1+SR


def test_an_address_that_lands_in_another_block_names_that_block(soc, image):
    """GPIOA's struct ends at +0x28; 0x4002_1000 is GPIOE, not a faraway GPIOA write."""
    a, _i, _ = sweep([insn(TEXT_BASE, "mov", f"r3, #0x{GPIOA + 0x1000:08X}"),
                      insn(TEXT_BASE + 2, "str", "r2, [r3]")], soc, image)
    assert list(a) == [("GPIOE", "MODER", "write")]


def test_an_address_past_the_last_block_gets_no_claim(soc, image):
    a, _i, _ = sweep([insn(TEXT_BASE, "mov", f"r3, #0x{GPIOA + 0x40:08X}"),
                      insn(TEXT_BASE + 2, "str", "r2, [r3]")], soc, image)
    assert a == {}


# ------------------------------------------------------------------------ the fold step

def test_fold_reports_direction_counts_and_escalates_confidence_with_volume(soc, image):
    accesses = {("USART1", "CR1", "write"): [Evidence(kind="instruction", note="x",
                                                      file_offset=0, vaddr=TEXT_BASE, hex="0068")] * 5,
                ("USART1", "SR", "read"): [Evidence(kind="instruction", note="y",
                                                    file_offset=2, vaddr=TEXT_BASE, hex="6868")]}
    findings = decode._fold(accesses, {}, soc, image,
                            {"engine": "capstone/test", "instructions": 100, "coverage": 0.5})
    f, = findings
    assert f.kind == "peripheral.access" and f.subject == "USART1"
    assert f.confidence == 0.86 and f.rule == "peripheral.access.tracked-base-register"
    assert f.metrics == {"accesses": 6, "registers": {"CR1/write": 5, "SR/read": 1}}
    assert f.evidence[0].hex and not validate([f])
    assert any("function boundaries" in u for u in f.unknowns)


def test_a_single_quiet_access_stays_below_the_confident_bar(soc, image):
    accesses = {("TIM2", "CR1", "write"): [Evidence(kind="instruction", note="x",
                                                    file_offset=0, vaddr=TEXT_BASE, hex="0060")]}
    f, = decode._fold(accesses, {}, soc, image,
                      {"engine": "capstone/test", "instructions": 8, "coverage": 0.1})
    assert f.confidence == 0.74


def test_immediate_sites_become_one_materialised_finding_not_a_claim_per_block(soc, image):
    imm = {("USART1", "CR1", None): [Evidence(kind="instruction", note="a", file_offset=0,
                                              vaddr=TEXT_BASE, hex="0068")] * 3,
           ("GPIOA", None, None): [Evidence(kind="instruction", note="b", file_offset=4,
                                             vaddr=TEXT_BASE, hex="0123")]}
    findings = decode._fold({}, imm, soc, image,
                            {"engine": "capstone/test", "instructions": 2000, "coverage": 0.42})
    f, = findings
    assert f.kind == "peripheral.materialised" and f.confidence == 0.7
    assert f.metrics["sites"] == 4 and f.metrics["peripherals"] == ["GPIOA", "USART1"]
    assert f.metrics["decode_coverage"] == 0.42 and f.metrics["instructions"] == 2000
    assert len(f.evidence) == 2 and not validate([f])
    assert any("MOVW/MOVT" in u for u in f.unknowns)


def test_no_immediates_means_no_materialised_finding(soc, image):
    assert decode._fold({}, {}, soc, image,
                        {"engine": "capstone/test", "instructions": 0, "coverage": 0.0}) == []


# ------------------------------------------------------------------- coverage of the map

QSPI_R = 0xA000_1000        # RM0433: STM32F765 quad-SPI control block, absent on F4
NOWHERE = 0x4400_0000       # no STM32 in the shipped databases maps this


def _sites(soc, image, addrs):
    return {a: decode._instruction_evidence(soc, a, TEXT_BASE + 4, image, "str",
                                             "r2, [r3]", "write", b"\x00\x68")
            for a in addrs}


def _gap(soc, others, image, addrs):
    unmapped = Counter(dict.fromkeys(addrs, 1))
    stats = {"engine": "capstone/test", "unmapped_device_accesses": len(addrs)}
    return decode._coverage_finding(soc, sorted(addrs), unmapped, _sites(soc, image, addrs),
                                    others, stats), stats


def test_an_address_no_installed_map_names_is_a_hole_not_a_wrong_part(soc, image):
    """The honest reading of a miss: the databases are incomplete, that is all we know."""
    f7 = load_soc("stm32f765xx")
    f, _ = _gap(soc, {"stm32f765xx": f7}, image, [NOWHERE])
    assert f.kind == "soc.coverage" and f.confidence == 0.45
    assert "no other installed map names them" in f.summary
    assert f.metrics == {"addresses": 1, "accesses": 1, "contested": 0, "contested_by": {},
                         "other_maps_compared": 1}
    assert not validate([f])


def test_an_address_another_map_does_name_is_allowed_to_threaten_the_match(soc, image):
    """The counter-evidence case: code reaches hardware the chosen part does not have."""
    f7 = load_soc("stm32f765xx")
    f, _ = _gap(soc, {"stm32f765xx": f7}, image, [QSPI_R, NOWHERE])
    assert f.confidence == 0.6
    assert "ARE in stm32f765xx" in f.summary
    assert f.metrics["contested"] == 1 and f.metrics["contested_by"] == {"stm32f765xx": 1}
    assert any(f"reached 0x{QSPI_R:08X}" in e.note for e in f.evidence)


def test_the_truncation_note_only_appears_when_the_list_really_was_truncated(soc, image):
    """A caveat about a limit that does not exist is as misleading as hiding one that does."""
    f7 = load_soc("stm32f765xx")
    small, _ = _gap(soc, {"stm32f765xx": f7}, image, [NOWHERE, QSPI_R])
    assert any("all 2 address(es) were compared" in u for u in small.unknowns)
    assert not any("lower bound" in u for u in small.unknowns)

    many = [0x4400_0000 + 0x100 * i for i in range(decode._UNMAPPED_LIST_CAP + 5)]
    big, _ = _gap(soc, {"stm32f765xx": f7}, image, many)
    assert any(f"only the first {decode._UNMAPPED_LIST_CAP} of {len(many)}" in u
               for u in big.unknowns)


def test_a_map_that_sees_everything_produces_no_coverage_finding(soc, image):
    """No gap, no claim: silence is the correct output when nothing is missing."""
    f, _ = _gap(soc, {}, image, [])
    assert f is None
    f2 = decode._coverage_finding(soc, [], Counter(), {}, {}, {"engine": "capstone/test",
                                                               "unmapped_device_accesses": 0})
    assert f2 is None


def test_the_unmapped_site_is_named_even_when_the_map_has_nothing_to_say(soc, image):
    """The evidence for a gap must still be re-checkable, so it quotes the target address."""
    f7 = load_soc("stm32f765xx")
    f, _ = _gap(soc, {"stm32f765xx": f7}, image, [NOWHERE])
    assert f"reached 0x{NOWHERE:08X}" in f.evidence[0].note
    assert f.evidence[0].vaddr == TEXT_BASE + 4 and f.evidence[0].file_offset == 4


# --------------------------------------------------------------------- string-level parsing

@pytest.mark.parametrize("ops,expected", [("#0x1000", 0x1000), ("r3, #0xc", 12),
                                          ("#-0x10", -16), ("[r3]", None)])
def test_immediate_parsing(ops, expected):
    assert decode._num(ops) == expected


@pytest.mark.parametrize("ops,expected", [("r3", 3), ("sp", 13), ("lr", 14), ("r12", 12),
                                          ("pc", 15), ("r16", None), ("sl", 10), ("r9", 9)])
def test_register_names_match_what_capstone_prints(ops, expected):
    assert decode._regnum(ops) == expected


@pytest.mark.parametrize("ops,expected", [("[r3, #0xc]", ("r3", 12)), ("[pc]", ("pc", 0)),
                                          ("[sp, #-0x10]", ("sp", -16)), ("[r4, r5]", None)])
def test_memory_operand_parsing(ops, expected):
    assert decode._mem(ops) == expected


def test_the_bare_ldr_pc_form_that_broke_the_old_regex_is_seen(soc, image):
    """Regression: the base-register pattern once required an "r" prefix, which made
    every literal-pool load invisible — most of what firmware does."""
    here = TEXT_BASE + 0x10
    lit = ((here + 4) & ~3) + 0x4
    seg = image.segments[0]
    seg.data = seg.data[:lit - TEXT_BASE] + struct.pack("<I", GPIOA) + seg.data[lit - TEXT_BASE + 4:]
    _a, i, _ = sweep([insn(here, "ldr", "r3, [pc, #0x4]")], soc, image)
    assert [k[0] for k in i] == ["GPIOA"]


def test_nearest_symbol_walks_backwards_and_respects_image_order(image):
    assert decode._nearest_symbol(image, TEXT_BASE + 0x42) == "dma_start"
    assert decode._nearest_symbol(image, TEXT_BASE - 4) is None
    empty = Image("e", 0, "raw", "arm", "little", None, [])
    assert decode._nearest_symbol(empty, 0) is None


def test_function_windows_are_bounded_by_the_next_symbol_and_capped(soc, image):
    stats = {"engine": "capstone/test", "bytes_decoded": 0, "instructions": 0, "segments": 1,
             "coverage": 0.0, "functions": 0, "resyncs": 0, "memory_hits": 0}
    windows = decode._function_windows(image, image.segments, 0x1000, stats)
    assert [w[1] for w in windows] == [0x0, 0x40]
    assert stats["functions"] == 2


def test_a_symbolless_segment_decodes_as_one_window_and_counts_a_resync(soc):
    seg = Segment(TEXT_BASE, bytes(64), "text", None, "raw", 0)
    img = Image("t", 64, "raw", "arm", "little", None, [seg])
    stats = {"resyncs": 0, "functions": 0}
    windows = decode._function_windows(img, [seg], 0x1000, stats)
    assert windows == [(seg, 0, 64)] and stats["resyncs"] == 1


# ------------------------------------------------------------------- the real sample

@pytest.mark.sample
def test_every_instruction_evidence_on_the_sample_matches_the_bytes_at_its_offset(elf_path, soc):
    """The report's whole value is that a reader can re-check it, so this asserts the
    chain end-to-end: offset quoted → bytes in the file → hex in the finding."""
    image = load(str(elf_path))
    findings, stats = decode.decode_code(image, soc, budget=0x40000)
    raw = elf_path.read_bytes()
    quoted = 0
    for f in findings:
        for e in f.evidence:
            assert e.file_offset is not None and e.hex, f"{f.subject}: {e.note}"
            n = len(e.hex) // 2
            assert raw[e.file_offset:e.file_offset + n] == bytes.fromhex(e.hex), \
                f"{f.subject} @0x{e.vaddr:X}: quoted bytes are not at {e.file_offset}"
            quoted += n
    assert quoted > 200 and stats["instructions"] > 20_000
    assert not validate(findings), validate(findings)


def test_the_sample_report_names_the_functions_that_touch_the_peripheral(elf_path, soc):
    image = load(str(elf_path))
    findings, _stats = decode.decode_code(image, soc, budget=0x40000)
    rcc = next(f for f in findings if f.subject == "RCC")
    notes = [e.note for e in rcc.evidence]
    assert all("  in " in n for n in notes), notes[:3]
    assert any("[read]" in n for n in notes) and any("[write]" in n for n in notes)


def test_without_capstone_the_engine_reports_nothing_and_says_why(soc, image, monkeypatch):
    monkeypatch.setattr(decode, "CAPSTONE", None)
    findings, stats = decode.decode_code(image, soc)
    assert findings == [] and stats == {"engine": None}
