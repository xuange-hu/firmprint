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
import subprocess
import sys

import pytest
from conftest import ROOT


def _load_module(name, path):
    """Checkout-only: a wheel does not ship `tools/`."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_checker():
    script = ROOT / "tools" / "check_doc_quotes.py"
    if not script.exists():
        pytest.skip("the checker lives in the repository checkout", allow_module_level=True)
    return _load_module("check_doc_quotes", script)


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


def test_a_transcript_with_the_tools_own_ellipsis_is_still_checked():
    """A marker used to mean "skip this block"; the CLI started printing one, so coverage fell.

    Shortening a hash in the header row puts `…` inside a *faithful* paste, and the run check
    treated any marker as a hand trim: the transcript stopped being compared and the checker
    still said ok, four quotes lighter.  Now an exact match is tried first and a marked paste
    falls back to ordered pieces, so lines assembled out of order still fail.
    """
    printed = ["file        firmware.bin  790,416 B  sha256:7b7fca163c0a266f…",
               "container   raw / arm  1 segment(s)  entry -",
               "match       stm32f427xx (f4, cortex-m4)  conf 0.66  best match"]
    corpus = chk.norm("\n".join(printed))
    text = chk.norm(" ".join(printed))
    assert "…" in text, "the marker has to be inside the run for this test to mean anything"
    assert chk.header_runs(printed) == [printed]
    assert text in corpus, "a faithful paste must still match exactly"
    assert chk.in_order(corpus, chk.elided_pieces(text))

    assembled = chk.norm(" ".join([printed[0], printed[2], printed[1]]))
    assert assembled not in corpus
    pieces = chk.elided_pieces(assembled)
    assert len(pieces) == 2, pieces
    assert not chk.in_order(corpus, pieces), "real lines in the wrong order is a fake run"


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


def test_the_test_count_in_the_readme_is_the_number_pytest_collects():
    """README promises "N tests"; the only honest source for N is the collector.

    That sentence has read 240+, 250 and 277 as the suite grew, and each one was true
    only for the commit that wrote it. A pinned number nobody can re-check is the same
    failure this whole file exists to prevent, just in a place the scan-output checker
    cannot see. `--collect-only` is not a test run, so this cannot recurse.
    """
    proc = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q"],
                          cwd=str(ROOT), capture_output=True, text=True, check=False)
    m = re.search(r"(\d+) tests? collected", proc.stdout)
    assert m, f"the collector said nothing useful ({proc.returncode}):\n{proc.stdout[-400:]}"
    collected = int(m.group(1))
    readme = (ROOT / "README.md").read_text(encoding="utf8")
    claimed = set(re.findall(r"python -m pytest -q\s+#\s*(\d+) tests", readme))
    assert claimed, "README no longer spells a test count the way this test can read it"
    assert claimed == {str(collected)}, (
        f"README claims {sorted(claimed)} tests, the suite collects {collected}")


def test_the_answer_keys_digest_line_is_the_one_the_gate_reads(tmp_path):
    """`verification/<board>.md` names the bytes it was generated from; the gate reads it.

    The parse is the whole of the "did the samples move?" check, so it is pinned against the
    exact sentence the generator writes -- and against a missing directory, which must yield
    no claims rather than a crash or a false pass.
    """
    v = tmp_path / "verification"
    v.mkdir()
    (v / "openmv2.md").write_text(
        "# Verification: openmv2 (STM32F427VGT6)\n"
        "\n"
        "- image: `firmware.elf`, 7,670,672 bytes, sha256 `" + "a" * 64 + "`\n"
        "- vendor part: **STM32F427VGT6**\n", encoding="utf8")
    assert chk.described_build(v) == {"openmv2/firmware.elf": "a" * 64}
    assert chk.described_build(tmp_path / "no-such-directory") == {}


def test_a_digest_the_generator_writes_is_a_digest_the_gate_can_read(tmp_path):
    """Two files share one line format, and only a synthetic round trip proves it.

    `make_verification.py` writes the promise and `check_doc_quotes.py` reads it back; the
    end-to-end equality test needs the firmware, so it can say *whether* the digests match but
    never whether either side parses the other's syntax.  Change one writer alone and the gate
    silently compares nothing -- the failure this repository keeps paying for, in the specific
    form of a green run that checked no bytes.
    """
    mk = _load_module("make_verification_quote_test", ROOT / "tools" / "make_verification.py")
    rep = {"meta": {"file": {"size": 790_416, "sha256": "d" * 64}}}
    line = mk.image_line(rep, ROOT / "samples" / "openmv2" / "firmware.bin")
    m = chk.IMAGE_LINE.match(line)
    assert m, f"the gate cannot parse the generator's own line: {line}"
    assert (m["name"], m["size"], m["sha"]) == ("firmware.bin", "790,416", "d" * 64)
    v = tmp_path / "verification"
    v.mkdir()
    (v / "openmv2.md").write_text(line + "\n", encoding="utf8")
    assert chk.described_build(v) == {"openmv2/firmware.bin": "d" * 64}


def test_moved_bytes_are_reported_as_moved_bytes_not_as_a_stale_quote():
    """The distinction this repo paid for on 2026-10-18.

    The runner scanned a build the fetcher had substituted for the pinned one, and the gate
    said "the prose is stale".  Both statements were true; only one was actionable, and the
    reader who acted on it would have rewritten correct documentation.
    """
    want, got = "b" * 64, "c" * 64
    assert chk.moved_samples({"openmv2/firmware.elf": got},
                             {"openmv2/firmware.elf": want}) == [
        f"  openmv2/firmware.elf: the scanner read sha256 {got[:16]}..., "
        f"the answer key describes {want[:16]}..."]
    assert not chk.moved_samples({"openmv2/firmware.elf": want},
                                 {"openmv2/firmware.elf": want})
    # an image the answer key says nothing about -- the synthetic blob, say -- is not drift
    assert not chk.moved_samples({"synthetic/blob.bin": got},
                                 {"openmv2/firmware.elf": want})


def test_a_digest_named_in_a_sentence_is_a_claim_about_bytes():
    """The case studies open by telling the reader which file to hash; that is checkable.

    Before this, a pasted report line carrying a digest was checked but a paragraph naming one
    was not -- so the sentence a confused reader follows after a bad download was the least
    verified digest in the repository.
    """
    real = "7b7fca163c0a266f" + "0" * 48
    digests = {"openmv2/firmware.bin": real}
    ok = "We will scan `firmware.bin`: 790,416 bytes, sha256 `7b7fca163c0a266f…`.  It is the\n"
    assert not chk.stale_digests(ok, digests, [], "openmv2")
    stale = ok.replace("7b7fca163c0a266f", "d6f222ce873ad53e")
    f, = chk.stale_digests(stale, digests, [], "openmv2")
    assert "d6f222ce873ad53e" in f and "no scanned image of this board" in f
    # a prefix is a claim about the whole file, so a prefix is short enough to fail
    assert len(chk.stale_digests(ok.replace("7b7fca163c0a266f", "7b7fca16"),
                                 digests, [], "openmv2")) == 0
    # a digest that exists but belongs to the other board is the mistake this scoping is for
    other = chk.stale_digests(ok, {"openmv3/firmware.bin": real}, [], "openmv2")
    assert other and "openmv3" in other[0]
    # inside a fenced block the paste is a transcript, already checked line by line
    assert not chk.stale_digests("```\nfile  firmware.bin  sha256:abcdef0123456789\n```\n",
                                 digests, [], "openmv2")
    # a header digest is a claim about the database, not about firmware
    assert not chk.stale_digests("header sha256 `" + "e" * 16 + "`", {}, ["e" * 64], "openmv2")
    assert chk.header_digests(ROOT / "src" / "firmprint" / "data"), \
        "the installed database must be able to account for its own headers"


def test_every_digest_the_prose_names_is_one_the_fetcher_pins():
    """Docs and pins have to agree before anyone downloads 91 MB.

    The end-to-end gate compares scanned bytes; this compares the two *promises* -- the
    digests in the prose and the digests in `tools/get_sample.py` -- so a re-pin that updates
    one and not the other fails in the dependency-free test job too.  Both sets have to equal
    the bytes, so agreeing with each other is necessary if not quite sufficient.
    """
    gs = _load_module("get_sample_docs", ROOT / "tools" / "get_sample.py")
    pins = {f"{b.lower()}/{name}": sha
            for b, (_prefix, _dest, board_pins) in gs.BOARDS.items()
            for name, sha in board_pins.items()}
    assert pins, "the fetcher holds no pins: nothing here can be believed"
    headers = chk.header_digests(ROOT / "src" / "firmprint" / "data")
    names = sorted(gs.BOARDS)
    for md in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
        board = chk.board_of(md, names)
        for bad in chk.stale_digests(md.read_text(encoding="utf8"), pins, headers, board):
            pytest.fail(f"{md.name}: {bad}")


def test_the_answer_key_refuses_to_describe_unpinned_bytes(monkeypatch, tmp_path):
    """`source_line()` is the last place that knows which release a document claims.

    Generating a document out of bytes nothing pins produces exactly the artifact this
    repository just spent an afternoon on: numbers with no way back to the file that made them.
    """
    mk = _load_module("make_verification_unpinned", ROOT / "tools" / "make_verification.py")
    monkeypatch.setattr(mk.fetch, "ASSET_SHA256", "")
    with pytest.raises(SystemExit, match="no archive digest"):
        mk.source_line()
    monkeypatch.setattr(mk.fetch, "ASSET_SHA256", "a" * 64)
    monkeypatch.setattr(mk.fetch, "BOARDS", {"OPENMV2": ("OPENMV2", tmp_path, {})})
    with pytest.raises(SystemExit, match="pins no files for OPENMV2"):
        mk.source_line()
    monkeypatch.setattr(mk.fetch, "BOARDS",
                        {"OPENMV2": ("OPENMV2", tmp_path, {"firmware.elf": "b" * 64})})
    line = mk.source_line()
    assert line.startswith(f"- source: OpenMV release `{mk.fetch.RELEASE}`")
    assert f"`{'a' * 64}`" in line and "python tools/get_sample.py --all" in line


def test_the_generator_and_the_gate_read_the_same_digest_lines():
    """Two sides of one contract, checked against the committed answer key.

    `make_verification.py` writes the `- image:` line and this file parses it; either may be
    edited alone, and the failure only shows up months later as a gate that silently compares
    nothing.  Every image the answer key quotes has to be named, not just the ELF: a moved
    `firmware.bin` is exactly as misleading as a moved `firmware.elf`.
    """
    described = chk.described_build(ROOT / "verification")
    assert described, "no verification/*.md to compare against"
    assert {"openmv2/firmware.elf", "openmv2/firmware.bin", "openmv2/openmv.bin",
            "openmv3/firmware.elf", "openmv3/firmware.bin", "openmv3/openmv.bin"} \
        <= set(described)
    for tag, sha in described.items():
        assert len(sha) == 64 and not set(sha) - set("0123456789abcdef"), tag


def test_the_answer_key_records_nothing_about_the_machine_that_ran_it():
    """A generated file you cannot reproduce byte for byte is not an answer key.

    `verification/*.md` used to end with `- runtimes: ELF 1.3s, raw 0.86s, … (3.12.10 /
    windows)`, which made the regeneration diff a *conditional*: CI normalised that line away
    and the PR template said "produces no diff (beyond the `runtimes:` line)".  An exception
    written into the definition of a check is a hole in it -- the next runner-dependent number
    simply joins the list.  A timing describes whoever ran the generator, and the interpreter
    version with it, so both are printed on stdout instead of being committed.
    """
    docs = sorted((ROOT / "verification").glob("*.md"))
    assert docs, "no verification/*.md to read"
    for md in docs:
        text = md.read_text(encoding="utf8")
        assert not re.search(r"^- runtimes:", text, re.M), f"{md.name}: a timing got committed"
        assert not re.search(r"\d+\.\d+s\b", text), f"{md.name}: a wall-clock duration survives"
        assert not re.search(r"\d+\.\d+\.\d+ / (windows|linux|darwin)", text), \
            f"{md.name}: the runner's interpreter and OS are not facts about the firmware"
    # and the generator still has to say something instead: the line it writes is a promise
    # about reproducibility, so a silent deletion of the timing is not enough
    assert any("re-running the generator has to leave it byte-identical" in d.read_text("utf8")
               for d in docs), "the answer key no longer states its own reproducibility rule"


def test_the_answer_key_hands_over_a_claim_it_did_not_shorten():
    """A quoted report line in `verification/*.md` is the line, not a window into it.

    The generator pasted the `soc.coverage` summary `[:200]` characters at a time, and on the
    pinned OpenMV2 build that cut the sentence at `1 of them ARE in stm32h74…` -- the answer
    key that exists so a stranger can check a claim ended in a truncated identifier and
    dropped the clause explaining what the rival map saw.  An ellipsis inside a *generated*
    document is different from one in a transcript: nothing upstream cut that text for width,
    the document did.
    """
    docs = {md.name: md.read_text(encoding="utf8")
            for md in sorted((ROOT / "verification").glob("*.md"))}
    assert docs, "no verification/*.md to read"
    quoted = [(name, line) for name, text in docs.items() for line in text.splitlines()
              if line.startswith("- the matched map is also judged on what it misses:")]
    assert quoted, "the answer key stopped quoting the `soc.coverage` row"
    for name, line in quoted:
        assert "…" not in line, f"{name}: a generated claim was cut short: {line[-60:]}"
        # the two endings this row can have; anything else means the document stopped
        # quoting the engine and started summarising it
        assert line.rstrip().endswith(("this one does not", "not evidence of a wrong part")), \
            f"{name}: the coverage claim does not end where the tool ends it: {line[-70:]}"
    for name, text in docs.items():
        for line in text.splitlines():
            assert not line.rstrip().endswith("…"), f"{name}: a line ends on a cut: {line[-60:]}"


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
    # 54 is what the prose carries today.  The floor exists because the count, not the exit
    # code, is the only signal that a check stopped running at all: the day the CLI began
    # printing its own `…` under a shortened hash, four transcripts fell out of the run check
    # and the gate said "ok" while covering less than it had the run before.
    assert n >= 50, f"the checker found only {n} quotes; its patterns are stale:\n{report}"
