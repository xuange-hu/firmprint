"""Tests for the tool that tests the documentation.

`tools/check_doc_quotes.py` exists because prose that pastes real report output goes stale
silently: a confidence rewritten to three decimals, a count that changed when a heuristic
was fixed.  A checker with a broken regex is worse than no checker -- it prints "ok" while
comparing nothing -- so the checker itself is pinned here, the same way the heuristics are:
each test states a stale quote and asserts the tool notices.

The end-to-end pass is opt-in (`FIRMPRINT_DOC_QUOTES=1`) because it re-scans all ten sample
images three times; CI's `verification` job runs `tools/check_doc_quotes.py` directly, so the
gate exists whether or not this test is enabled.
"""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import re
import sys

import pytest
from conftest import ROOT


def _load_checker():
    """Checkout-only: a wheel does not ship `tools/`."""
    script = ROOT / "tools" / "check_doc_quotes.py"
    if not script.exists():
        pytest.skip("the checker lives in the repository checkout", allow_module_level=True)
    spec = importlib.util.spec_from_file_location("check_doc_quotes", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


chk = _load_checker()

REAL = {
    "kind": "peripheral.access",
    "subject": "DCMI",
    "confidence": 0.86,
    "engine": "capstone/5.0.7",
    "rule": "peripheral.access.tracked-base-register",
    "summary": "DCMI: 6 decoded load/store(s) through a tracked base register; CR/read=4, CR/write=2",
    "metrics": {"accesses": 6, "exclusive_constants": 0},
    "evidence": [{"kind": "instruction", "vaddr": "0x080465AC", "bytes": "9a60",
                  "note": "ldr r2, [r3]  [read]  reached 0x50050000 -> DCMI+0x000 (CR)"}],
    "unknowns": ["base-register tracking resets at function boundaries"],
}


def test_a_fragment_that_elides_and_rewraps_still_matches():
    """The docs are allowed to shorten a quote, not to change what it says."""
    frag = {"kind": "peripheral.access", "subject": "DCMI", "confidence": 0.86,
            "summary": "6 decoded load/store(s)"}
    assert chk.subset(frag, REAL)


@pytest.mark.parametrize("frag", [
    {"kind": "peripheral.access", "subject": "DCMI", "confidence": 0.85},
    {"kind": "peripheral.access", "subject": "DCMI", "metrics": {"accesses": 265}},
    {"kind": "peripheral.access", "subject": "DCMI",
     "summary": "DCMI: 6 decoded load/store(s) through an untracked base"},
    {"kind": "peripheral.access", "subject": "DCMI", "confidence_band": "high"},
    {"kind": "peripheral.access", "subject": "DCMI",
     "evidence": [{"vaddr": "0x080465AC", "bytes": "beef"}]},
])
def test_a_stale_number_or_an_invented_field_is_not_a_subset(frag):
    """The whole point: `265` where the run printed `6` must fail, not paraphrase-match.

    The last case also pins that a *list* is matched item by item -- a doc pastes the one
    evidence record it cares about, not all 24.
    """
    assert not chk.subset(frag, REAL)


def test_a_prose_line_is_not_mistaken_for_a_padded_header():
    """"file offset 430" is English; "file   firmware.bin  790,416 B" is a CLI row.

    Conflating them made every prose sentence starting with one of those words a "quote"
    the checker had to fail on.
    """
    assert chk.HEADER.match("candidates  stm32f427xx=89 constants/81 blocks")
    assert chk.HEADER.match("container   raw / arm  1 segment(s)  entry -")
    assert not chk.HEADER.match("file offset 430 is where the table starts")
    assert not chk.HEADER.match("container note: capstone not installed")


def test_the_finding_row_regex_needs_the_columns():
    """A sentence like "peripheral.usage is 0.82" must not parse as a quoted row."""
    assert chk.FINDING.match("peripheral.usage  GPIOE  0.82  GPIOE @0x40021000 ...")
    assert not chk.FINDING.match("peripheral.usage is 0.82 because carve is weaker")


def test_an_unpadded_quote_is_caught_instead_of_silently_skipped():
    """The failure mode of the tightened regex: a real row pasted with single spaces.

    `FINDING` requires the CLI's column padding, so an unpadded row would simply stop
    being checked -- a silent pass.  `LOOSE` is what turns that into a reported problem.
    """
    s = "peripheral.usage GPIOE 0.82 GPIOE @0x40021000 referenced 24 times"
    assert not chk.FINDING.match(s)
    m = chk.LOOSE.match(s)
    assert m and m.group(1).startswith(chk.KINDS) and m.group(2) not in chk.NOT_A_SUBJECT


def test_a_sentence_inside_a_block_stays_a_sentence():
    """"soc.candidate is 0.76" is prose about a row, and flagging it would be noise."""
    for s in ("soc.candidate is 0.76 on the F7 image",
              "memory.reference is 0.82 whenever carve agrees"):
        m = chk.LOOSE.match(s)
        assert m and m.group(2) in chk.NOT_A_SUBJECT, s


def test_whitespace_flattening_survives_a_rewrap():
    """Docs wrap at 80 columns; the CLI did not wrap that way on the terminal that printed it."""
    got = chk.flat("GPIOE @0x40021000 referenced 24 times as an address\n"
                   "                               constant; registers seen: MODER(24)")
    assert got == ("GPIOE @0x40021000 referenced 24 times as an address constant; "
                   "registers seen: MODER(24)")


def test_a_different_library_version_is_not_a_stale_quote():
    """`capstone/5.0.9` over the same bytes is a property of the runner, not of the claim.

    The distribution version and capstone's own `__version__` already disagree (the 5.0.9
    wheel prints `capstone/5.0.7`), so comparing engine labels literally would make the
    docs gate fail on a `pip install --upgrade` instead of on a wrong number.  The engine
    *name* still has to match.
    """
    frag = {"kind": "peripheral.access", "subject": "DCMI", "engine": "capstone/5.0.7"}
    assert chk.subset(frag, {**REAL, "engine": "capstone/5.0.9"})
    assert not chk.subset({"kind": "peripheral.access", "subject": "DCMI",
                           "engine": "carve/1"}, REAL)


def test_header_runs_group_a_transcript_but_not_a_lonely_line():
    """A multi-line quote is checked as a *contiguous* run; a single line is not a run.

    This is what catches a transcript that drops a printed line: every line left in it is
    real, so the per-line check passes, while the run -- `file`, `container`, its note,
    `match` -- is no longer anything the tool printed.  That is how the OpenMV3 case study
    lost the container note that explains the inferred load base.
    """
    lines = ["file        firmware.bin  790,416 B  sha256:7b7fca163c0a266f",
             "container   raw / arm  1 segment(s)  entry -",
             "            raw dump: no container header. load base inferred as 0x08010000",
             "            Pass --base to pin it.",
             "match       stm32f427xx (f4, cortex-m4)  conf 0.66  best match",
             "",
             "kind                    subject              conf  summary",
             "-" * 40,
             "peripheral.usage  GPIOE  0.82  GPIOE @0x40021000 referenced 24 times"]
    assert [len(r) for r in chk.header_runs(lines)] == [5]
    assert chk.header_runs(["contract    0 violation(s)", ""]) == []


def test_a_dropped_note_line_breaks_the_run():
    """The specific staleness: same lines, minus the CLI's explanation of the guess.

    Two adjacent header lines are still a run -- and the run is what fails, because the
    live report prints the note between them.
    """
    full = ["container   raw / arm  1 segment(s)  entry -",
            "            load base inferred as 0x08010000: of the 16 origins tested",
            "match       stm32f427xx (f4, cortex-m4)  conf 0.66  best match"]
    live = chk.norm("\n".join(full))
    trimmed = [full[0], full[2]]
    runs = chk.header_runs(trimmed)
    assert [len(r) for r in runs] == [2]
    assert chk.norm(" ".join(runs[0])) not in live


def test_a_json_fence_that_does_not_parse_is_still_classified_as_json(tmp_path):
    """The bug worth catching is a ```json block that is not valid JSON.

    Classifying by parse success would drop it into the prose bucket and check it as text,
    which is exactly how a line-wrapped string inside a quoted finding stopped being an
    error for a while.
    """
    md = tmp_path / "x.md"
    md.write_text('```json\n{"kind": "soc.candidate",\n "summary": "unclosed\n```\n',
                  encoding="utf8")
    blocks = chk.quoted(md, want_json=True)
    assert len(blocks) == 1
    with pytest.raises(json.JSONDecodeError):
        json.loads(blocks[0][1])
    assert chk.quoted(md, want_json=False) == []


# ------------------------------------------------------------------- the prose layer

def test_a_claim_written_across_a_line_break_is_still_a_claim():
    """Docs wrap at 80 columns; a number and its noun must not be separated by that choice.

    The sentence and its paraphrase are the same assertion, and both have to be found -- a
    checker that only sees the unwrapped one reports the wrapped one as an unchecked 0.
    """
    md = "addresses.  28\nfurther blocks were reported that the oracle has no name\n" \
         "for (ETH, SDIO)."
    folded = chk.prose_units(md)
    assert folded == ["addresses. 28 further blocks were reported that the oracle has no "
                      "name for (ETH, SDIO)."]
    claims = chk.prose_claims(md)
    assert [(n, w) for n, w, _c in claims] == [("28", "blocks")], claims
    assert "28 further blocks" in claims[0][2]


def test_a_table_row_is_not_folded_into_its_neighbouring_cell():
    """A count in one cell must not become a claim about the word in the next column.

    Folding whole blocks together turned every comparison table into invented assertions;
    rows stay separate units, so each cell's number is only read against nouns in its own
    cell.
    """
    units = chk.prose_units("| board | blocks | findings |\n|---|---|---|\n"
                            "| OpenMV2 | 81 | 107 |\n\nthe prose continues here")
    assert units[-1] == "the prose continues here"
    assert "| OpenMV2 | 81 | 107 |" in units
    # `81` is not a claim about `findings`, and `107` is not a claim about anything: what
    # follows a cell's number is a pipe, and a noun has to be a word
    assert chk.prose_claims("| OpenMV2 | 81 | 107 |") == []


def test_prose_that_is_not_about_a_report_quantity_is_left_alone():
    """`128 KB bootloader` and `Thumb-2 instructions` are facts about other things.

    The noun list is what makes this check about the tool's own output; these are the
    shapes that used to fire, and each is now a claim about nothing.
    """
    for text in ("OpenMV3 puts a 128 KB bootloader in front of the firmware.",
                 "decoded Thumb-2 instructions (with capstone)",
                 "UART (2). RTC's row is confirmed by carve alone",
                 "Python 3.10 or newer is required."):
        assert chk.prose_claims(text) == [], text


def test_a_comma_grouped_count_is_not_read_as_its_first_three_digits():
    """"202,041 instructions" is one number; "202 instructions" is a different claim.

    Without the comma guards, the regex fell back to the three-digit prefix and then found
    the noun two words later, so a table cell passed by accidentally matching a row of the
    wrong image.
    """
    claims = chk.prose_claims("| OpenMV2 | `stm32f427xx` | 14/14 | 0 | 202,041 instructions "
                              "decoded |")
    assert claims == [("202,041", "instructions", claims[0][2])], claims
    assert not any(n == "202" for n, _w, _c in claims)


@pytest.mark.parametrize("noun, printed", [
    ("tables", "2 table(s)"), ("accesses", "42 access(es)"), ("violations", "0 violation(s)"),
    ("findings", "107 findings"), ("blocks", "81 blocks"), ("slots", "131 slots")])
def test_the_cli_parenthetical_plural_is_the_same_claim_as_prose(noun, printed):
    """`f"{n} table(s)"` and "2 vector tables" have to be comparable, or every row count in
    the docs is checked against a spelling nobody prints."""
    assert chk.claims_printed(printed, printed.split()[0], noun), printed


def test_a_number_from_the_other_board_is_not_this_boards_answer():
    """The point of scoping a case study to its own runs: a copied count must fail.

    33 is a real number this tool prints -- for OpenMV3 -- which is exactly why a corpus of
    every image lets the OpenMV2 doc quote it and pass.
    """
    live = "counts  openmv2/firmware.elf json: 28 blocks the driver oracle cannot name"
    assert chk.claims_printed(live, "28", "blocks")
    assert not chk.claims_printed(live, "29", "blocks")
    assert not chk.claims_printed(live, "33", "blocks")
    assert chk.board_of(chk.ROOT / "docs" / "case-openmv2.md", ["openmv2", "openmv3"]) == "openmv2"
    assert chk.board_of(chk.ROOT / "README.md", ["openmv2", "openmv3"]) is None


def test_a_quoted_row_is_checked_against_the_board_that_printed_it():
    """Scoping has to reach the row quotes, not only the numbers in sentences.

    The same `peripheral.access/RCC/0.86` triple is real on both boards with a different
    count, so a corpus holding both boards accepts either quote and catches neither: the F4
    study could paste the F7 row, every field would still "match a real run", and the gate
    would print ok.
    """
    f4 = ["peripheral.access       RCC                  0.86  RCC: 182 decoded load/store(s)"
          " through a tracked base register"]
    f7 = ["peripheral.access       RCC                  0.86  RCC: 265 decoded load/store(s)"
          " through a tracked base register"]
    triple = ("peripheral.access", "RCC", "0.86")
    v4, v7 = chk.view(f4, []), chk.view(f7, [])
    assert [t for t in v4["pairs"][triple] if "182" in t]
    assert not any("182" in t for t in v7["pairs"][triple])
    assert "182" in v4["lines"] and "182" not in v7["lines"]
    assert "265" in v7["text"] and "265" not in v4["text"]
    # and a fragment is matched only against findings of the same board
    frag = {"kind": "peripheral.access", "subject": "RCC", "summary": "RCC: 182 decoded"}
    assert chk.subset(frag, {"kind": "peripheral.access", "subject": "RCC",
                             "summary": "RCC: 182 decoded load/store(s)"})
    assert not any(chk.subset(frag, f) for f in v7["findings"])


@contextlib.contextmanager
def _clean_argv():
    """The checker reads argv; a test must not inherit pytest's."""
    saved = sys.argv
    sys.argv = ["check_doc_quotes.py"]
    try:
        yield
    finally:
        sys.argv = saved


@pytest.mark.skipif(not os.environ.get("FIRMPRINT_DOC_QUOTES"),
                    reason="set FIRMPRINT_DOC_QUOTES=1 (CI runs the checker directly)")
def test_the_repo_prose_passes_and_is_actually_checked(capsys):
    """End-to-end over README.md and docs/case-*.md, against live scans.

    The assertion on `checked` is the one that matters: a checker whose regexes stopped
    matching prints the same "ok" as a checker that found nothing stale.
    """
    images = sorted(p for p in (ROOT / "samples").glob("*/*")
                    if p.suffix in (".bin", ".elf") and p.is_file())
    if not images:
        pytest.skip("run `python tools/get_sample.py --all` to check the prose")
    with _clean_argv():
        rc = chk.main()
    report = capsys.readouterr().out
    assert rc == 0, report
    n = int(re.search(r"(\d+) quoted fragments/lines checked", report).group(1))
    assert n >= 40, f"the checker found only {n} quotes; its patterns are stale:\n{report}"
