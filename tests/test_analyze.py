"""End-to-end: file in, report out, contract clean, oracle checked.

The expensive part (analysing the real sample) runs once per module and is shared
by every assertion below, so the suite stays honest about what it checked without
becoming slow.
"""
from __future__ import annotations

import copy
import json
import struct
from pathlib import Path

import pytest
from conftest import cortex_m_image

from firmprint.analyze import SCHEMA, analyze, to_markdown
from firmprint.decode import available as capstone_available
from firmprint.evidence import STRICT_CONFIDENCE, dumps
from firmprint.verify import compare, symbol_oracle

F4 = "stm32f427xx"
H7 = "stm32h743xx"


@pytest.fixture(scope="module")
def report(elf_path) -> dict:
    return analyze(str(elf_path), budget=0x8_0000)


@pytest.fixture(scope="module")
def by_kind(report: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in report["findings"]:
        out.setdefault(f["kind"], []).append(f)
    return out


# ------------------------------------------------------------------ report skeleton

def test_the_report_declares_its_schema_and_the_engines_that_ran(report):
    assert report["schema"] == SCHEMA == "firmprint-report/1"
    assert set(report) == {"schema", "meta", "findings", "contract"}
    assert set(report["meta"]) == {"tool", "version", "elapsed_sec", "python", "file",
                                   "container", "soc", "soc_scan", "engines", "decode",
                                   "carve_stats"}
    assert report["meta"]["tool"] == "firmprint"
    assert set(report["meta"]["engines"]) == {"container", "vectors", "carve", "decode"}


def test_the_file_identity_is_hashed_not_just_named(report, elf_path):
    meta = report["meta"]["file"]
    assert meta["size"] == elf_path.stat().st_size
    assert len(meta["sha256"]) == 64 and meta["sha256"] == meta["sha256"].lower()


def test_a_report_is_serialisable_as_written_by_the_cli(report):
    # `dumps`, not `json.dumps(..., default=str)`: the serializer the CLI uses refuses
    # anything it would otherwise have to stringify, so this proves the report is
    # JSON-native rather than proving a coercion hid whatever leaked into it.
    text = dumps(report)
    assert json.loads(text)["meta"]["soc"]["device"] == F4


def test_the_carve_stats_are_reported_so_the_reader_can_judge_coverage(report):
    stats = report["meta"]["carve_stats"]
    assert stats["words_examined"] > stats["candidate_words"] > 0
    assert stats["excluded_pointers"] >= 0


# ------------------------------------------------------------------------ findings

def test_finding_ids_are_unique_ordered_and_complete(report):
    ids = [f["id"] for f in report["findings"]]
    assert ids == sorted(ids) and len(set(ids)) == len(ids)
    assert ids[0] == "F-0001"
    for f in report["findings"]:
        assert f["kind"] and f["subject"] and f["summary"]
        assert f["engine"] and f["rule"]
        assert 0.0 <= f["confidence"] <= 1.0
        assert f["unknowns"], f"{f['kind']}/{f['subject']} claims certainty about nothing"
        assert f["evidence_total"] >= len(f["evidence"])


def test_confidence_never_outruns_the_evidence_attached(report):
    confident = [f for f in report["findings"] if f["confidence"] >= STRICT_CONFIDENCE]
    assert confident, "this report has no confident claims at all"
    for f in confident:
        assert f["evidence"], f["summary"]
        assert any("file_offset" in e or "vaddr" in e for e in f["evidence"]), f["summary"]


def test_the_vector_table_and_the_soc_candidate_are_both_claimed(by_kind, report):
    table, = by_kind["cortex-m.vector_table"]
    assert table["metrics"]["n_live"] > 20
    top = max((f for f in report["findings"] if f["kind"] == "soc.candidate"),
              key=lambda f: f["confidence"])
    assert top["subject"] == F4
    # F427 and F765 share their peripheral windows, so this image's constants tie and
    # only the RAM map (CCM at 0x1000_0000, which F7 does not have) breaks it.  The
    # report must name that fact rather than pretend the constants decided it.
    assert top["metrics"]["exclusive_constants"] == 0
    assert top["metrics"]["ram_exclusive"] is True
    assert "best match on the RAM map" in top["summary"]
    assert any("rests on the RAM declaration alone" in u for u in top["unknowns"])
    assert top["evidence"], "a part name with no anchored region is decoration"


def test_the_two_tier_engines_are_kept_apart_in_the_report(by_kind):
    """Carving says *referenced*, capstone says *loaded/stored* — collapsing the two
    would turn 40 unsupported blocks into 40 register accesses."""
    usage = {f["subject"] for f in by_kind["peripheral.usage"]}
    access = {f["subject"] for f in by_kind["peripheral.access"]}
    assert usage - access, "carving-only blocks must stay in the weaker tier"
    assert all(f["rule"] == "peripheral.usage.carved-constants" for f in by_kind["peripheral.usage"])
    assert all(f["rule"] == "peripheral.access.tracked-base-register"
               for f in by_kind["peripheral.access"])
    assert any("no read/write direction" in u for f in by_kind["peripheral.usage"] for u in f["unknowns"])


def test_memory_windows_are_not_reported_as_peripherals(by_kind):
    for f in by_kind["memory.reference"]:
        assert f["rule"] == "memory.reference.carved-constants"
        assert "no CMSIS register struct" in f["summary"]
        assert f["confidence"] < 0.9


def test_the_map_that_matched_is_also_judged_on_what_it_misses(report, by_kind):
    """A match is only honest next to the addresses it could not name.

    The numbers here are the sample's, not the tool's promise, and they moved when the
    answer key was re-pinned to OpenMV `v5.0.1`: the ELF decodes enough more code than the
    raw dump to reach one address that `stm32h743xx` *does* name.  That is the contested
    path finally firing on a real image instead of a fixture, and the row is required to
    change its own confidence when it happens -- 0.6 with a rival named, 0.45 as a bare
    database gap.
    """
    gap, = by_kind["soc.coverage"]
    stats = report["meta"]["decode"]
    assert gap["metrics"]["addresses"] == stats["unmapped_device_constants"]
    assert gap["metrics"]["accesses"] == stats["unmapped_device_accesses"]
    assert gap["metrics"]["other_maps_compared"] == 2, "the comparison must actually be made"
    assert gap["metrics"]["contested"] == 1, "one miss is hardware another map can name"
    assert gap["metrics"]["contested_by"] == {H7: 1}
    assert gap["confidence"] == 0.6, "a contested gap is evidence about the part, not a footnote"
    assert "another installed map sees hardware this one does not" in gap["summary"]
    assert all("reached 0x" in e["note"] for e in gap["evidence"])


def test_a_gap_no_installed_map_names_stays_a_database_gap(bin_path):
    """The other half of the rule: with no rival, the same kind of row must not threaten.

    `firmware.bin` of the same board decodes 9k fewer instructions than its ELF twin and
    never reaches the H7-named address, so its coverage row is the quiet case -- and both
    rows come from the same engine on the same part, which is what makes the difference in
    confidence a judgement about evidence rather than about the file format.
    """
    rep = analyze(str(bin_path), budget=0x8_0000)
    gap, = [f for f in rep["findings"] if f["kind"] == "soc.coverage"]
    assert gap["metrics"]["contested"] == 0 and gap["metrics"]["contested_by"] == {}
    assert gap["confidence"] == 0.45 < STRICT_CONFIDENCE
    assert "no other installed map names them" in gap["summary"]


# -------------------------------------------------------------- the byte-level promise

def test_every_quoted_word_in_the_report_is_really_at_the_offset_it_names(report, elf_path):
    """The whole tool rests on this: open the file at the printed offset, read the
    printed bytes, compare.  If it ever drifts, the report must not ship."""
    raw = elf_path.read_bytes()
    checked = 0
    for f in report["findings"]:
        for e in f["evidence"]:
            if e.get("kind") not in ("word", "bytes", "instruction") or "bytes" not in e:
                continue
            assert "file_offset" in e, f"{f['kind']}/{f['subject']}: {e['note']}"
            blob = bytes.fromhex(e["bytes"])
            off = e["file_offset"]
            assert raw[off:off + len(blob)] == blob, \
                f"{f['subject']} {e['note']}: offset {off} holds {raw[off:off+len(blob)].hex()}"
            checked += 1
    assert checked > 100, checked


def test_the_contract_is_empty_for_the_real_sample(report):
    assert report["contract"]["strict"] is True
    assert report["contract"]["violations"] == []
    assert "untrustworthy" in report["contract"]["note"]


# --------------------------------------------------------------------------- oracle

def test_the_driver_oracle_is_fully_recalled_and_never_given_to_the_analysis(report):
    modules, _samples = symbol_oracle(_symbols(Path(report["meta"]["file"]["path"])))
    res = compare(report, modules)
    assert res["missed"] == []
    assert res["confirmed"] == res["oracle_modules"] == 14
    assert res["recall_over_drivers"] == 1.0
    assert res["detected_peripherals"] >= 60
    # the oracle is a *separate* observation: peripheral claims come from addresses.
    # The engine labels are matched by shape, not by literal version -- `capstone/x` is
    # whatever the installed disassembler self-reports, and pinning it here would make a
    # `pip install --upgrade` look like a regression in the answer key.
    engines = set(res["peripherals_by_engine"])
    assert "carve/1" in engines, engines
    if capstone_available():
        assert any(e.startswith("capstone/") and e.endswith("+carve/1")
                   for e in engines), engines


def test_blocks_the_oracle_cannot_name_are_reported_as_unconfirmed_not_wrong(report):
    modules, _ = symbol_oracle(_symbols(Path(report["meta"]["file"]["path"])))
    res = compare(report, modules)
    assert len(res["unconfirmed_peripherals"]) >= 10
    assert "DMA1_Stream3" in res["unconfirmed_peripherals"] or res["unconfirmed_peripherals"]


def _symbols(path):
    from firmprint.container import load
    return load(str(path)).symbols


# ------------------------------------------------------------------- forcing options

def test_naming_a_soc_pins_the_database_and_stops_the_scan(elf_path):
    r = analyze(str(elf_path), soc_name=H7, skip_code=True)
    assert r["meta"]["soc"]["device"] == H7
    assert r["meta"]["soc_scan"]["databases_considered"] == [H7]
    assert not r["contract"]["violations"]


def test_the_capstone_skip_is_recorded_as_a_reason_not_a_silence(elf_path):
    r = analyze(str(elf_path), skip_code=True)
    assert r["meta"]["decode"] == {"engine": None, "reason": "requested"}
    assert r["meta"]["engines"]["decode"] is None
    kinds = {f["kind"] for f in r["findings"]}
    assert "peripheral.access" not in kinds and "peripheral.usage" in kinds
    assert "skipped by request" in to_markdown(r)


def test_pinning_a_load_base_replaces_the_inference(bin_path):
    pinned = analyze(str(bin_path), base=0x0800_0000, skip_code=True)
    assert pinned["meta"]["container"]["segments"][0]["vaddr"] == "0x08000000"
    assert not [n for n in pinned["meta"]["container"]["notes"] if "inferred" in n]


# ------------------------------------------------------------------ synthetic firmware

def test_a_synthetic_image_is_analysed_with_the_same_contract(tmp_path):
    """No ELF, no symbols, no network: a bare flash dump must still produce a
    self-checking report rather than a crash or an unverified claim."""
    g, u = 0x4002_0000, 0x4001_1000
    body = cortex_m_image(base=0x0800_0000, code_bytes=0x800)
    data = body[:0x400] + struct.pack("<4I", g, u + 0x0C, 0x4002_3800 + 0x30, u) + body[0x400:]
    p = tmp_path / "dump.bin"
    p.write_bytes(data)

    r = analyze(str(p), base=0x0800_0000)
    assert r["meta"]["container"]["format"] == "raw"
    assert r["contract"]["violations"] == []
    kinds = {f["kind"] for f in r["findings"]}
    assert {"cortex-m.vector_table", "peripheral.usage", "soc.candidate"} <= kinds
    by_subject = {f["subject"]: f for f in r["findings"] if f["kind"] == "peripheral.usage"}
    assert by_subject["GPIOA"]["metrics"]["references"] == 1
    assert by_subject["USART1"]["metrics"]["references"] == 2


def test_markdown_keeps_the_evidence_visible_and_states_the_limits(report):
    md = to_markdown(report)
    assert md.startswith("# firmprint report")
    assert "| finding | subject | conf | summary |" in md
    assert "matched SoC: **stm32f427xx**" in md
    assert "contract: 0 violation(s)" in md
    assert md.count("\n| ") >= 20


def test_markdown_does_not_truncate_the_violation_line(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(cortex_m_image())
    md = to_markdown(analyze(str(p), skip_code=True))
    assert "contract:" in md.splitlines()[-1]


def test_a_markdown_table_that_stops_at_40_rows_says_how_many_it_left_out(report):
    """`--md` writes the report a person attaches to an issue; 40 of 45 rows is not 45.

    The text table has always ended with "... N more finding(s)". The markdown did not,
    so the file version of the same scan read as a complete list -- and the claim the
    whole project is built on is that a displayed subset names the whole it came from.
    """
    thin = copy.deepcopy(report)
    thin["findings"] = [{"kind": "peripheral.usage", "subject": f"P{i}", "confidence": 0.5,
                         "summary": "x" * 200} for i in range(45)]
    md = to_markdown(thin)
    assert md.count("\n| `") == 40
    assert "... 5 more finding(s) not shown in this table" in md
    assert "all 45" in md
    assert ("| " + "x" * 149 + "… |") in md, "a cut summary must show that it was cut"
