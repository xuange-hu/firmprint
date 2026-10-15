"""The evidence contract itself.

This module is the reason the project exists: a claim is only as good as the
bytes behind it, and `validate()` is what makes that machine-checkable instead
of a promise in a README.  Tests here are written to fail loudly if the bar is
loosened — a contract nobody can test is a contract that quietly decays.
"""
from __future__ import annotations

import json

from firmprint.evidence import (
    SCHEMA,
    STRICT_CONFIDENCE,
    Evidence,
    Finding,
    iter_numbered,
    render_json,
    sha256_file,
    validate,
)


def finding(kind="cortex-m.vector_table", subject="table@0x08000000", confidence=0.9,
           evidence=(), **kw) -> Finding:
    return Finding(kind=kind, subject=subject, confidence=confidence,
                   summary="test claim", engine="test/1", rule="test.rule",
                   evidence=list(evidence), **kw)


def word(off=0, hex_="00000240") -> Evidence:
    return Evidence(kind="word", note="0x40020000", file_offset=off, vaddr=0x4002_0000, hex=hex_)


# ---------------------------------------------------------------------- the strict bar

def test_a_confident_claim_with_no_evidence_is_a_violation():
    problems = validate([finding(confidence=0.9)])
    assert problems == ["cortex-m.vector_table/table@0x08000000: confidence 0.90 but zero evidence"]


def test_the_bar_is_inclusive_at_exactly_the_threshold():
    assert validate([finding(confidence=STRICT_CONFIDENCE)])
    assert validate([finding(confidence=STRICT_CONFIDENCE - 0.01)]) == []


def test_an_uncertain_claim_may_legitimately_have_nothing_to_show():
    f = finding(confidence=0.4, unknowns=["nothing to quote"])
    assert validate([f]) == []


def test_unanchored_evidence_does_not_count_as_proof():
    """`evidence=[Evidence(note="somewhere")]` is decoration; a reader cannot check it."""
    f = finding(evidence=[Evidence(kind="region", note="somewhere")])
    assert any("file offset or virtual address" in p for p in validate([f]))
    assert validate([finding(evidence=[Evidence(kind="region", vaddr=0x0800_0000, count=4096)])]) == []
    assert validate([finding(confidence=0.4,
                             evidence=[Evidence(kind="region", note="somewhere")])]) == []


def test_confidence_must_stay_inside_the_declared_range():
    assert any("out of range" in p for p in validate([finding(confidence=1.4)]))
    assert any("out of range" in p for p in validate([finding(confidence=-0.01)]))
    assert validate([finding(confidence=1.0, evidence=[word()])]) == []


# ------------------------------------------------------------- per-kind evidence rules

def test_byte_and_word_evidence_must_quote_bytes():
    assert any("missing bytes" in p for p in
               validate([finding(evidence=[Evidence(kind="bytes", note="8 bytes")])]))
    assert any("missing bytes" in p for p in
               validate([finding(evidence=[word(hex_=None)])]))
    assert validate([finding(evidence=[Evidence(kind="bytes", hex="deadbeef",
                                                 file_offset=16)])]) == []


def test_word_evidence_must_say_where_in_the_file_it_came_from():
    assert any("missing file offset" in p for p in
               validate([finding(evidence=[word(off=None)])]))
    assert validate([finding(evidence=[word()])]) == []


def test_a_violation_names_the_finding_it_punishes():
    problems = validate([finding(kind="peripheral.usage", subject="USART1", evidence=[word(hex_=None)])])
    assert len(problems) == 1
    assert problems[0].startswith("peripheral.usage/USART1:")


def test_clean_reports_validate_to_an_empty_list():
    f = finding(evidence=[word(), Evidence(kind="instruction", note="ldr", file_offset=4,
                                           vaddr=0x0800_0100, hex="0068", text="ldr r0, [r0]")])
    assert validate([f]) == []


# ------------------------------------------------------------------------ serialisation

def test_evidence_serialisation_omits_what_it_does_not_have():
    d = Evidence(kind="word", note="n", file_offset=8, vaddr=0x4002_0000, hex="00000240").to_dict()
    assert d == {"kind": "word", "note": "n", "file_offset": 8,
                 "vaddr": "0x40020000", "bytes": "00000240"}
    assert "hex" not in d and "count" not in d and "text" not in d
    assert Evidence(kind="region", vaddr=0x0800_0000, count=4096).to_dict() == \
        {"kind": "region", "note": "", "vaddr": "0x08000000", "count": 4096}


def test_a_finding_shows_the_first_twelve_quotes_but_reports_all_of_them():
    f = finding(evidence=[word(off=i) for i in range(30)])
    d = f.to_dict("F-0001")
    assert len(d["evidence"]) == 12 and d["evidence_total"] == 30
    assert d["id"] == "F-0001"
    assert "id" not in f.to_dict()


def test_confidence_is_rounded_without_being_rewritten():
    assert finding(confidence=0.8654).to_dict()["confidence"] == 0.865
    assert finding(confidence=1 / 3).to_dict()["confidence"] == 0.333


def test_add_returns_the_finding_so_chains_stay_readable():
    f = finding()
    assert f.add(word()).add(word(off=4)) is f
    assert len(f.evidence) == 2


# ----------------------------------------------------------------------------- ids

def test_finding_ids_follow_confidence_then_kind_then_subject():
    rows = [finding(kind="soc.candidate", subject="b", confidence=0.5, evidence=[word()]),
            finding(kind="peripheral.usage", subject="Z", confidence=0.9, evidence=[word()]),
            finding(kind="peripheral.usage", subject="A", confidence=0.9, evidence=[word()]),
            finding(kind="cortex-m.vector_table", subject="t", confidence=0.7, evidence=[word()])]
    got = [(fid, f.kind, f.subject) for fid, f in iter_numbered(rows)]
    assert got == [("F-0001", "peripheral.usage", "A"),
                   ("F-0002", "peripheral.usage", "Z"),
                   ("F-0003", "cortex-m.vector_table", "t"),
                   ("F-0004", "soc.candidate", "b")]


def test_ids_are_padded_to_four_digits_and_start_at_one():
    ids = [fid for fid, _f in iter_numbered([finding(evidence=[word()]) for _ in range(40)])]
    assert ids[0] == "F-0001" and ids[9] == "F-0010" and ids[39] == "F-0040"


def test_iter_numbered_does_not_consume_or_mutate_its_input():
    rows = [finding(evidence=[word()])]
    assert list(iter_numbered(rows)) == list(iter_numbered(rows))
    assert rows[0].confidence == 0.9


# -------------------------------------------------------------------------- json / hash

def test_render_json_produces_parseable_output_with_a_trailing_newline():
    report = {"schema": SCHEMA, "findings": [finding(evidence=[word()]).to_dict("F-0001")]}
    text = render_json(report)
    assert text.endswith("\n")
    assert json.loads(text)["schema"] == "firmprint-finding/1"


def test_render_json_survives_the_types_the_report_actually_uses():
    assert "1" in render_json({"n": 1, "b": b"x".hex(), "p": None, "t": (1, 2)})


def test_sha256_is_the_digest_of_the_bytes_whether_they_come_from_disk_or_memory(tmp_path):
    blob = bytes(range(64))
    p = tmp_path / "f.bin"
    p.write_bytes(blob)
    import hashlib
    assert sha256_file(blob) == sha256_file(str(p)) == hashlib.sha256(blob).hexdigest()
