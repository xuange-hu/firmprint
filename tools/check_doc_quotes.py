#!/usr/bin/env python3
"""Check that every number and report line quoted in the prose is what the tool prints.

The README and `docs/case-*.md` paste real output.  Prose drifts: a confidence gets
rewritten to three decimals, a summary gets paraphrased, a count changes because a
heuristic was fixed.  Each of those is a documentation bug of the worst kind, because the
whole argument of this project is that a claim comes with its evidence.

So the quotes are machine-checked, in five ways:

  * the bytes come first: every scanned image is compared with the digest
    `verification/<board>.md` says it was generated from, and a difference is reported as
    *moved samples* rather than as stale prose -- because a fetcher that silently downloads
    a different build makes every quote below fail for a reason the reader cannot fix;
  * a digest a *sentence* names ("790,416 bytes, sha256 `7b7f…`") has to be the digest of an
    image this checker scanned, or of a header the installed database was generated from --
    the case studies open by inviting the reader to hash the file themselves, and that
    invitation is the least checked claim in the repository;
  * a ```json fragment must be a *subset* of some real finding (every key it shows has to
    carry that finding's value, strings matched as substrings because the docs elide);
  * a text-shaped `kind subject conf` line, a header line (`match`, `candidates`,
    `decoded`, `contract`, `engines`, `file`, `container`) and any run of them quoted as a
    transcript must match a real run;
  * a number in a *sentence* -- outside the fenced blocks -- that names a report quantity
    ("the 81 `peripheral.usage` rows", "28 further blocks", "stops after 24 consecutive
    unused slots") must be printed by some real run.  This is the check that catches the
    worst kind of doc bug, an illustrative number that was never measured; the fix is either
    to say it without inventing a count or to make the number real, because the corpus here
    is derived from runs and from the documented constants it reads out of `cli` and
    `vectors`, never typed in.

Usage:
    python tools/check_doc_quotes.py            # needs samples/ fetched
    python tools/check_doc_quotes.py --list     # show what was checked
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if (ROOT / "src").exists():                                   # run from a checkout
    sys.path.insert(0, str(ROOT / "src"))

from firmprint import cli, decode, vectors  # noqa: E402

DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
KINDS = ("cortex-m", "soc", "peripheral", "memory", "region", "container")
HEADERS = ("file", "container", "match", "candidates", "engines", "decoded", "contract")
FINDING = re.compile(r"^([a-z][a-z0-9._-]*(?:\.[a-z_]+)?)\s{2,}(\S+)\s{2,}(0\.\d{2,3})\b")
# A row the CLI printed is column-padded; prose that merely *mentions* a confidence is not
# ("capped at 0.66 and prefixed ...").  Requiring the padding is what keeps an English
# sentence from being checked as a quote -- and LOOSE is what keeps the opposite mistake, a
# real quote written without padding, from being silently skipped instead of reported.
LOOSE = re.compile(r"^([a-z][a-z0-9._-]*(?:\.[a-z_]+)?)\s+(\S+)\s+(0\.\d{2,3})\b")
# what the second column of a real row never is: an English word.  "soc.candidate is 0.76"
# inside a code block is a sentence about a row, not a row, and reporting it as a
# formatting problem would train people to ignore the checker.
NOT_A_SUBJECT = {"is", "are", "was", "were", "at", "in", "on", "of", "to", "by", "as",
                 "and", "or", "but", "with", "that", "this", "it", "we", "be", "not",
                 "has", "have", "sits", "scores", "reads", "prints", "means", "gets"}
# the padded column headers the CLI prints; a prose line that merely starts with one of
# these words ("container note:", "file offset 430") is not a header quote
HEADER = re.compile(rf"^({'|'.join(HEADERS)})\s{{2,}}\S")


def flat(text: str) -> str:
    """Collapse whitespace so a re-wrapped quote still matches the run that produced it."""
    return re.sub(r"\s+", " ", text)


# The engine label carries whatever version the disassembler library self-reports, and that
# is a property of the machine reading the docs, not of the firmware or of the claim: the
# wheel that ships capstone 5.0.9 prints `capstone/5.0.9` over the same bytes that made
# these quotes.  Normalising the version token is the difference between a checker that
# catches a stale count and one that fails on every runner update.  Nothing else about an
# engine label is allowed to differ.
ENGINE_VER = re.compile(r"capstone/\d[\w.+-]*")


def norm(text: str) -> str:
    """Whitespace-collapsed, with the runner-dependent library version folded out."""
    return flat(ENGINE_VER.sub("capstone/", text))


def blocks(text: str) -> list[tuple[str, str]]:
    """(fence language, body) for every fenced block; the language is on the fence line."""
    return [(lang.strip(), body) for lang, body in re.findall(r"```([^\n]*)\n(.*?)```", text, re.S)]


def subset(frag: dict, real: dict) -> bool:
    """Every key the fragment shows must carry the real value (strings as substrings)."""
    for key, want in frag.items():
        got = real.get(key)
        if isinstance(want, str):
            if not isinstance(got, str) or norm(want) not in norm(got):
                return False
        elif isinstance(want, dict):
            if not isinstance(got, dict) or not subset(want, got):
                return False
        elif isinstance(want, list):
            if not isinstance(got, list):
                return False
            for item in want:
                if isinstance(item, dict):
                    if not any(subset(item, g) for g in got if isinstance(g, dict)):
                        return False
                elif item not in got:
                    return False
        elif got != want:
            return False
    return True


SYNTH_DIR = ROOT / "reports" / "docquotes-synthetic"


def synthetic_image() -> Path | None:
    """The blob a stranger builds before downloading anything, under `reports/` (gitignored).

    The README tells them what `firmprint scan blob.bin --strict` answers, and a claim about
    the first thing a reader is told to run is a claim the docs gate should cover.  None if
    this is an installed wheel without `tools/`.
    """
    script = ROOT / "tools" / "make_synthetic.py"
    if not script.exists():
        return None
    spec = importlib.util.spec_from_file_location("make_synthetic", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    blob = SYNTH_DIR / "synthetic" / "blob.bin"
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(module.build())
    return blob


def run_all(images: list[Path]) -> tuple[list[dict], list[str], dict[str, list[str]],
                                         dict[str, list[dict]], dict[str, str]]:
    """Return (every finding, the whole live corpus, the corpus and the findings per board,
    and the digest every image was read under).

    The digest comes from the report the scanner printed, not from a second hash of the file
    on disk: the question it answers is "what did the tool actually see", and re-reading the
    image here would answer it with a hash nobody scanned.  It exists so that a *moved
    sample* is reported as moved bytes rather than as stale prose -- see `described_build`.

    The corpus is the printed text of every scan *plus* the counts nobody prints in a
    sentence's own words: total findings per image, findings per kind, the same two for a
    `--no-code` run, the per-map exclusivity the ranking is built on, the score the symbol
    oracle gives an ELF, and `socdb list`.  Prose asserts things like "the 81
    `peripheral.usage` rows" and "33 blocks were reported that the oracle cannot name", and a
    checker that only reads the report body cannot tell whether they are true.

    Every added line is *derived from a real run*, never typed in: the numbers in it are
    recomputed here from the same report objects the CLI printed.

    The per-directory grouping exists because a case study is about one board: "28 further
    blocks" in the OpenMV2 write-up is a claim about *OpenMV2*, and a corpus that also holds
    OpenMV3's runs lets a wrong number pass because some other image happens to print it.
    """
    from firmprint.container import load
    from firmprint.verify import compare, symbol_oracle

    findings: list[dict] = []
    lines: list[str] = []
    by_board: dict[str, list[str]] = {}
    board_findings: dict[str, list[dict]] = {}
    digests: dict[str, str] = {}
    for path in images:
        tag = f"{path.parent.name}/{path.name}"
        board = by_board.setdefault(path.parent.name, [])
        seen = board_findings.setdefault(path.parent.name, [])
        full: dict = {}
        for args, sink in ((["scan", str(path), "--format", "json", "--max-findings", "10000"],
                            "json"),
                           (["scan", str(path), "--format", "text", "--max-findings", "10000"],
                            "text"),
                           (["scan", str(path), "--format", "json", "--no-code",
                             "--max-findings", "10000"], "no-code")):
            if sink == "json" and not decode.available():
                args.append("--no-code")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(args)
            if rc != 0:
                raise SystemExit(f"scan failed on {path.name} ({rc}): {buf.getvalue()[:200]}")
            if sink == "text":
                printed = buf.getvalue().splitlines()
                lines.extend(printed)
                board.extend(printed)
                continue
            report = json.loads(buf.getvalue())
            got = report["findings"]
            if sink == "json":
                findings.extend(got)
                seen.extend(got)
                full = report
                digests[tag] = report.get("meta", {}).get("file", {}).get("sha256", "")
            v = len(report.get("contract", {}).get("violations", []))
            counts = [f"counts  {tag} {sink}: {len(got)} findings, {v} violations"]
            for kind in sorted({f["kind"] for f in got}):
                n = sum(1 for f in got if f["kind"] == kind)
                # grammatical, because a doc that says "1 row of `cortex-m.vector_table`"
                # has to find that exact phrase in the corpus to be believed
                counts.append(f"counts  {tag} {sink}: {n} {'row' if n == 1 else 'rows'} "
                              f"of {kind}")
            lines.extend(counts)
            board.extend(counts)
        # the metric the ranking reports and the prose quotes: how much of the image only
        # this map can see
        derived = []
        for f in full.get("findings", []):
            if f["kind"] == "soc.candidate":
                m = f.get("metrics", {})
                for key, words in (("exclusive_constants", "exclusive constants"),
                                   ("blind_constants", "constants this map cannot see"),
                                   ("constants_explained", "constants explained")):
                    if key in m:
                        derived.append(f"counts  {tag}: {f['subject']} {m[key]} {words}")
        # an ELF carries its own truth, and `verify` scores it; the docs quote that score
        if path.suffix == ".elf":
            modules, _samples = symbol_oracle(load(str(path)).symbols)
            if modules:
                r = compare(full, modules)
                derived += [
                    f"counts  {tag} oracle: {len(r['unconfirmed_peripherals'])} blocks the "
                    f"driver oracle cannot name",
                    f"counts  {tag} oracle: {r['confirmed']}/{r['oracle_modules']} drivers "
                    f"confirmed",
                    f"counts  {tag} oracle: {r['detected_peripherals']} peripheral blocks "
                    f"with address evidence"]
        lines.extend(derived)
        board.extend(derived)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli.main(["socdb", "list"])
    # `socdb list` is the installed database and the documented limits are properties of the
    # tool, not of one image, so they belong to every board's corpus as well as the whole
    shared = buf.getvalue().splitlines() + [
        # the row cap of the text table, the gap that ends a vector-table scan and how many
        # ranked maps survive as candidates: no scan prints any of these unless it happens to
        # hit the limit, so read them out of the source and let a doc quote them only while
        # the code still does
        f"defaults  the text table caps at {cli.DEFAULT_MAX_FINDINGS} findings",
        f"defaults  the vector scan stops after {vectors.MAX_GAP} consecutive unused slots",
        f"defaults  only the top {vectors.CANDIDATE_RANKINGS} ranked maps become candidates"]
    lines.extend(shared)
    for board_lines in by_board.values():
        board_lines.extend(shared)
    return findings, lines, by_board, board_findings, digests


#: the line `tools/make_verification.py` writes for every image it scanned
IMAGE_LINE = re.compile(r"^- image: `(?P<name>[^`]+)`, (?P<size>[\d,]+) bytes, "
                        r"sha256 `(?P<sha>[0-9a-f]{64})`")


def described_build(verification: Path) -> dict[str, str]:
    """`board/file` -> the sha256 that board's answer key says it scanned.

    The answer key is generated, so it carries the digest of the bytes it was built from,
    and reading it back here costs nothing.
    """
    out: dict[str, str] = {}
    for md in sorted(verification.glob("*.md")) if verification.is_dir() else []:
        for line in md.read_text(encoding="utf8").splitlines():
            if m := IMAGE_LINE.match(line.strip()):
                out[f"{md.stem}/{m['name']}"] = m["sha"]
    return out


def moved_samples(digests: dict[str, str], described: dict[str, str]) -> list[str]:
    """Every image whose scanned bytes differ from the bytes the answer key describes.

    This distinction is the whole point.  On 2026-10-18 the doc gate failed on CI and said
    the prose was stale; the prose was current and the *samples* had moved, because the
    fetcher pulled a rolling `development` asset and printed a note when its digest did not
    match.  A gate that reports "your documentation lies" when the real event is "the bytes
    under analysis changed" sends the reader to fix the wrong thing -- and teaches everyone
    to distrust the gate.
    """
    out = []
    for tag, sha in sorted(digests.items()):
        want = described.get(tag)
        if want is not None and want != sha:
            out.append(f"  {tag}: the scanner read sha256 {sha[:16]}..., "
                       f"the answer key describes {want[:16]}...")
    return out


#: a digest asserted by a *sentence* rather than pasted from a report
PROSE_SHA = re.compile(r"sha256[: ]+`?([0-9a-f]{12,64})")
#: where the installed SoC database says each generated map came from
HEADER_SHA = re.compile(rb'"header_sha256"\s*:\s*"([0-9a-f]{64})"')


def header_digests(data_dir: Path) -> list[str]:
    """The digests of the CMSIS headers the installed database was generated from.

    A sentence can quote one of those instead of an image digest, and the samples are not
    evidence for it -- so it has to be knowable from the same place the tool reads maps.
    """
    out = []
    for p in sorted(data_dir.glob("*.json")) if data_dir.is_dir() else []:
        out += [m.group(1).decode() for m in HEADER_SHA.finditer(p.read_bytes())]
    return out


def stale_digests(text: str, digests: dict[str, str], headers: list[str],
                  board: str | None) -> list[str]:
    """Problems for every digest a sentence names that no file this checker knows has.

    The case studies open with an invitation: "scan `firmware.bin`: 790,416 bytes, sha256
    `7b7f…` -- it is the application half of OpenMV2's flash".  That is the strongest claim in
    this repository, a claim about exact bytes, and it was typed by hand into a paragraph while
    the digests the *tool* prints were checked.  It is also the sentence a reader follows when
    the download gives them something else.  A prefix counts as a claim, so a prefix is short
    enough to fail; a doc scoped to one board may only name that board's images, because the
    other board's digest quoted here would otherwise pass by accident.
    """
    out = []
    want = (board or "").lower()
    for m in PROSE_SHA.finditer(prose(text)):
        sha = m.group(1)
        if any(d.startswith(sha) for d in headers):
            continue
        scope = [d for tag, d in digests.items()
                 if (board is None or tag.split("/")[0].lower() == want) and d.startswith(sha)]
        if scope:
            continue
        holders = sorted({tag.split("/")[0] for tag, d in digests.items() if d.startswith(sha)})
        hint = (f" -- that is the digest of {' and '.join(holders)}, "
                f"not of {'the image this doc is about' if board else 'any scanned image'}"
                if holders else "")
        out.append(f"prose names sha256 {sha[:16]}... but no scanned image"
                   f"{' of this board' if board else ''} (nor a database header) has "
                   f"that digest{hint}: {flat(text[max(0, m.start() - 40):m.end() + 30])}")
    return out


def quoted(md: Path, want_json: bool) -> list[tuple[str, str]]:
    """Fenced blocks of one kind: JSON report fragments, or plain-text quotes.

    Classified by whether the fence says json *or* the body parses as JSON containing a
    `kind` key -- a ```json fence whose body does not parse is exactly the bug worth
    reporting, so it has to be caught by the language, not by the parse.
    """
    out = []
    for lang, body in blocks(md.read_text(encoding="utf8")):
        tagged = lang.startswith("json")
        parses = False
        if not tagged and '"kind"' in body:
            try:
                json.loads(body)
                parses = True
            except Exception:                                 # noqa: BLE001
                parses = False
        if (tagged or parses) == want_json:
            out.append((lang, body))
    return out


def header_runs(lines: list[str]) -> list[list[str]]:
    """Consecutive runs of padded header lines plus their indented continuation lines.

    A single quoted header line is checked one at a time elsewhere; this is about *runs*,
    because a transcript that drops a line the CLI prints -- the container note explaining
    an inferred load base, say -- is stale even though every line left in it is real.
    """
    runs: list[list[str]] = []
    run: list[str] = []
    for line in lines + [""]:
        s = line.strip()
        indent = len(line) - len(line.lstrip())
        if HEADER.match(s) or (run and s and indent >= 4):
            run.append(s)
        else:
            if len(run) >= 2:
                runs.append(run)
            run = []
    return runs


def in_order(corpus: str, frags: list[str]) -> bool:
    """Every fragment appears in the corpus, and each one after the previous.

    Order is the part that catches an assembled transcript: two real lines from two
    different runs both exist in the corpus, and only the sequence says they were never
    printed next to each other.
    """
    at = 0
    for f in frags:
        i = corpus.find(f, at)
        if i < 0:
            return False
        at = i + len(f)
    return True


def elided_pieces(text: str) -> list[str]:
    """Split a transcript at elision markers, dropping the markers themselves.

    Both the tool's own `…` (a hash shortened for the column) and a hand-written ` ... `
    land here; what a caller loses is the adjacency *across* the marker, which is exactly
    the thing that was being thrown away when a marked transcript skipped its run check.
    """
    return [p for p in (norm(x) for x in re.split(r"…| ?\.\.\. ?", text)) if p]


# The nouns a number in prose is claiming about this tool's own output.  Deliberately
# narrow: `128 KB bootloader` and `Python 3.10` are facts about the firmware and the
# interpreter, and what makes a claim checkable is that it names a report quantity.
# Widening this list was tried (`bytes`, `entries`, `items`, `symbols`, `fields`) and it
# produced false alarms of a specific kind: those numbers are true, but the report prints
# `790,416 B` and `(8 zeroed, 25 non-code)`, so adjacency to the doc's word fails.  A noun
# belongs here only when the tool itself prints that word next to the number.
NOUNS = ("findings?", "instructions?", "blocks?", "constants?", "access(?:es)?",
         "slots", "handlers", "violations?", "structs?", "maps?", "registers",
         "origins", "tables?", "times", "sites", "rows?", "columns?", "functions?")
# a number is only "about" a noun when nothing but a lowercase word or two separates them --
# the alternative turns every pipe-delimited table cell into a claim about its neighbour, and
# `(?<![\w.#,])` / `(?![.\dx,])` keep "202" from being read out of "202,041"
NUMBER = re.compile(r"(?<![\w.#,-])(?!\d+x)(\d{1,3}(?:,\d{3})+|\d+)(?![.\dx,-])")
CLAIM = re.compile(
    rf"{NUMBER.pattern}\s+(?:[a-z][a-z0-9`_.-]*\s+){{0,2}}\b({'|'.join(NOUNS)})\b")
# the same pair, searched in the live corpus, with the gap opened up by one word: easier to
# satisfy there than here, so a claim that is real is never lost to formatting
PRINTED = r"\b%s\s+(?:\S+\s+){0,3}%s"


def singular(noun: str) -> str | None:
    """The stem a generated row would print for this plural, or None if it has none.

    English here, not the CLI's: `tables` -> `table`, `accesses` -> `access`, and `access`
    stays `access` rather than becoming `acces`.
    """
    if noun.endswith(("ses", "xes", "zes", "ches", "shes")):
        return noun[:-2]
    if noun.endswith("s") and not noun.endswith(("ss", "us", "is")):
        return noun[:-1]
    return None


def noun_pattern(noun: str) -> str:
    """`tables` also matches the generated spellings `table` and `table(s)`.

    Prose pluralises the way people do; this CLI pluralises the way `f"{n} table(s)"` does,
    so the check has to know that "2 vector tables" and "2 table(s)" are the same claim.
    Only the corpus side gets this licence -- a doc that writes a wrong count still fails.
    The boundaries live inside each alternative because `table(s)` cannot end with `\\b`.
    """
    out = [r"\b" + re.escape(noun) + r"\b"]
    stem = singular(noun)
    if stem:
        out += [r"\b" + re.escape(stem) + r"\b", r"\b" + re.escape(stem) + r"\(s\)"]
    return "(?:" + "|".join(out) + ")"


def prose(text: str) -> str:
    """The markdown *outside* fenced blocks -- the sentences, not the pasted reports."""
    return re.sub(r"```[^\n]*\n.*?```", "\n", text, flags=re.S)


def prose_units(text: str) -> list[str]:
    """Paragraphs with their line wrapping folded out; table rows kept one per unit.

    Wrapping has to go, or "`peripheral.usage` rows" at the end of a line never reaches the
    "81" at the start of the next and a true claim is reported as false.  Table rows must
    *stay* separate, or the count in one cell becomes a claim about the word in the next
    column and every table in the docs turns into invented assertions.
    """
    units: list[str] = []
    para: list[str] = []

    def flush() -> None:
        if para:
            units.append(flat(" ".join(para)))
            para.clear()

    for line in prose(text).splitlines():
        s = line.strip()
        if not s:
            flush()
        elif s.startswith("|"):
            flush()
            units.append(s)
        else:
            para.append(s)
    flush()
    return units


def prose_claims(text: str) -> list[tuple[str, str, str]]:
    """(number, noun, context) for every report-shaped number the sentences assert.

    The noun is captured exactly as written, singular or plural, because the other side of
    the comparison is generated text with the same spelling.
    """
    out = []
    for unit in prose_units(text):
        for m in CLAIM.finditer(unit):
            out.append((m.group(1), m.group(2), unit[max(0, m.start() - 40):m.end() + 40].strip()))
    return out


def claims_printed(live: str, number: str, noun: str) -> bool:
    """Does some real run print that number within three words of that noun?

    Checked against the corpus with its line structure kept (only the engine version folded
    out), so a run's own wrapped summary still counts but two unrelated lines cannot be
    stitched into a claim the tool never made.
    """
    return re.search(PRINTED % (re.escape(number), noun_pattern(noun)), live) is not None


def corpus(lines: list[str]) -> str:
    """A run corpus with the runner-dependent bit normalised and the line breaks kept."""
    return "\n".join(ENGINE_VER.sub("capstone/", ln) for ln in lines)


def board_of(md: Path, names: list[str]) -> str | None:
    """Which sample directory a document is about, judged from its own filename.

    README and the security note talk about every board, so they get the whole corpus; a case
    study is scoped to the board it is a case study of, because a number that only some
    *other* image prints is a stale quote rather than a passing claim.
    """
    stem = md.stem.lower()
    hits = [n for n in names if n.lower() in stem]
    # the answer is lower-cased because that is how a board is spelled everywhere this
    # checker reads it -- `samples/openmv2`, `verification/openmv2.md` -- while the fetcher
    # spells its targets `OPENMV2`.  Returning the caller's spelling is what made a
    # correctly-pinned digest look like it belonged to the wrong board.
    return hits[0].lower() if len(hits) == 1 else None


def view(ls: list[str], fs: list[dict]) -> dict:
    """One corpus, ready to check a document against.

    Scoping is the point: the quoted row, the pasted JSON fragment and the number in a
    sentence are all claims about *this* board's image, and a corpus holding the other
    board's runs lets a wrong one pass because some unrelated line happens to print it.
    """
    # (kind, subject, conf@2dp) -> the summaries the tool printed for that triple
    pairs: dict[tuple[str, str, str], list[str]] = {}
    for line in ls:
        s = line.strip()
        if m := FINDING.match(s):
            pairs.setdefault(m.groups()[:3], []).append(norm(s[m.end():].strip()))
    # and the same triples from the JSON, where nothing is truncated at the column:
    # a doc may quote further into a summary than the text table ever printed
    summaries: dict[tuple[str, str, str], list[str]] = {}
    for f in fs:
        key = (f["kind"], str(f["subject"])[:19], f"{f['confidence']:.2f}")
        summaries.setdefault(key, []).append(norm(f["summary"]))
    return {
        # the corpus with its lines intact, for prose claims: `norm` folds newlines away,
        # which is right for matching a re-wrapped quote and wrong for deciding whether a
        # run ever printed a number next to a noun
        "lines": corpus(ls),
        # the same corpus collapsed to one string, for a transcript that may have been
        # re-wrapped by hand
        "text": norm("\n".join(ls)),
        "pairs": pairs,
        "summaries": summaries,
        "findings": fs,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true", help="print each quote that was checked")
    a = ap.parse_args()

    # a Windows console is a GBK console, and the reports this checker echoes contain
    # `✓` and non-breaking spaces; failing to print a finding is not the same as having no
    # finding, so let the undisplayable bytes escape rather than crash the gate
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")

    images = sorted(p for p in (ROOT / "samples").glob("*/*")
                    if p.suffix in (".bin", ".elf") and p.is_file())
    if not images:
        print("no samples: run `python tools/get_sample.py --all` first "
              "(the dependency-free CI job does not need this check)")
        return 0

    # the image the README tells a stranger to make before downloading anything is part of
    # the corpus, so a sentence about what `scan blob.bin` answers is checked too
    blob = synthetic_image()
    if blob is not None:
        images = [*images, blob]
    findings, lines, boards, board_finds, digests = run_all(images)
    shutil.rmtree(SYNTH_DIR, ignore_errors=True)
    # say it once, before the quote list, so a reader who stops at the first screen of
    # output stops at the reason rather than at the symptom
    moved = moved_samples(digests, described_build(ROOT / "verification"))
    if moved:
        print("THE SAMPLES MOVED -- these images are not the build `verification/*.md` "
              "was generated from:")
        for line in moved:
            print(line)
        print("Every quote failure below compares prose against a *different* image than "
              "the one it was written from, so it is not evidence that the documentation "
              "lied.  Fix the bytes first: `python tools/get_sample.py --all` to fetch the "
              "pinned build, or `--allow-drift --show-pins` plus "
              "`python tools/make_verification.py` to re-pin the answer key to these bytes, "
              "then re-run this check.\n")
    # one view per board plus the whole corpus; a document picks its view by filename, so a
    # quote in the OpenMV3 study is checked against OpenMV3 runs and nothing else
    names = sorted(boards)
    views = {"*": view(lines, findings)}
    views.update({n: view(boards[n], board_finds.get(n, [])) for n in names})
    # the database the *installed* package carries, not the checkout's: a sentence about a
    # header digest means the header this reader's `socdb list` is built from
    headers = header_digests(Path(cli.__file__).parent / "data")
    problems: list[str] = []
    checked = 0

    for md in DOCS:
        rel = md.relative_to(ROOT)
        board = board_of(md, names)
        v = views[board or "*"]
        for _lang, block in quoted(md, want_json=True):
            try:
                frag = json.loads(block)
            except Exception as exc:                            # noqa: BLE001
                problems.append(f"{rel}: a ```json quote is not valid JSON: {exc}")
                continue
            for item in (frag if isinstance(frag, list) else [frag]):
                if not (isinstance(item, dict) and "kind" in item):
                    continue
                checked += 1
                if not any(subset(item, f) for f in v["findings"]):
                    problems.append(f"{rel}: quoted finding fragment matches no real run: "
                                    f"{json.dumps(item)[:120]}")
        for _lang, block in quoted(md, want_json=False):
            block_lines = block.splitlines()
            for i, line in enumerate(block_lines):
                s = line.strip()
                m = FINDING.match(s)
                if m and m.group(1).startswith(KINDS) and "..." not in s and "…" not in s:
                    checked += 1
                    if a.list:
                        print(f"  quote  {rel}: {s[:70]}")
                    triple = m.groups()[:3]
                    if triple not in v["pairs"]:
                        problems.append(f"{rel}: {s[:70]} -- no real run prints that "
                                        f"{m.group(1)}/{m.group(2)} at {m.group(3)}")
                        continue
                    # the prose after the confidence is part of the quote: a doc that says
                    # "264 decoded load/store(s)" when the run printed 265 is the exact bug
                    # this file exists to catch
                    tail = [s[m.end():]]
                    for nxt in block_lines[i + 1:]:
                        # a wrapped summary is indented to the summary column; a sub-line
                        # like "  evidence  0x08..." is part of the finding's evidence, not
                        # of the quoted prose, and must end the tail
                        if len(nxt) - len(nxt.lstrip()) < 4 or FINDING.match(nxt.strip()):
                            break
                        tail.append(nxt.strip())
                    quoted_tail = norm(" ".join(tail)).split("…")[0].split(" ...")[0].strip()
                    if quoted_tail and not any(
                            quoted_tail in t or t.startswith(quoted_tail)
                            for t in v["pairs"][triple]) and not any(
                            quoted_tail in sm for sm in v["summaries"].get(triple, [])):
                        problems.append(f"{rel}: {m.group(1)}/{m.group(2)} at "
                                        f"{m.group(3)} is real, but no run prints the "
                                        f"summary quoted here: {quoted_tail[:70]}")
                elif (lm := LOOSE.match(s)) and lm.group(1).startswith(KINDS) \
                        and lm.group(2) not in NOT_A_SUBJECT \
                        and "..." not in s and "…" not in s:
                    problems.append(f"{rel}: {s[:70]} -- looks like a quoted finding row "
                                    f"but is not column-padded, so this checker would skip "
                                    f"it; re-paste it the way the CLI prints it")
                elif HEADER.match(s):
                    head = norm(s.split("…")[0].split(" ...")[0].rstrip(". "))
                    checked += 1
                    if a.list:
                        print(f"  quote  {rel}: {head[:70]}")
                    if head not in v["text"]:
                        problems.append(f"{rel}: header line not printed by any real run of "
                                        f"{board or 'the documented images'}: {head[:70]}")
            for run in header_runs(block_lines):
                text = norm(" ".join(run))
                # A transcript carrying an elision marker used to be skipped whole -- which is
                # how a checker quietly loses coverage: the CLI now prints its own `…` at the
                # end of a shortened hash, so a faithful paste became "deliberately trimmed"
                # and stopped being compared at all.  Exact match is still the first try; when
                # it fails, every piece between markers has to be real and appear in the order
                # the CLI prints them, so a line lifted from another run is still caught.
                checked += 1
                if a.list:
                    print(f"  run    {rel}: {text[:70]}")
                if text in v["text"]:
                    continue
                frags = elided_pieces(text)
                if frags and in_order(v["text"], frags):
                    continue
                problems.append(
                    f"{rel}: {len(run)} header lines quoted as one transcript, but no run "
                    f"prints them consecutively -- a line was dropped or taken from "
                    f"another image: {text[:80]}")

    for md in DOCS:
        rel = md.relative_to(ROOT)
        name = board_of(md, names)
        live = views[name or "*"]["lines"]
        text = md.read_text(encoding="utf8")
        for bad in stale_digests(text, digests, headers, name):
            checked += 1
            problems.append(f"{rel}: {bad}")
        for num, noun, where in prose_claims(text):
            checked += 1
            if a.list:
                print(f"  claim  {rel}: {num} {noun}  << {where}")
            if claims_printed(live, num, noun):
                continue
            # the same number printed by a *different* board is the failure mode this scoping
            # exists to catch, so name the corpus that does have it rather than leave a mystery
            elsewhere = [b for b in names
                         if b != name and claims_printed(views[b]["lines"], num, noun)]
            hint = ""
            if elsewhere:
                who = " and ".join(elsewhere)
                hint = (f" -- only {who} {'prints' if len(elsewhere) == 1 else 'print'} it, "
                        f"and this is not a doc about {'it' if len(elsewhere) == 1 else 'them'}")
            problems.append(f"{rel}: prose says {num} {noun}, but no run of the sample this "
                            f"doc is about prints that{hint}: {where}")

    print(f"doc quotes: {len(findings)} findings from {len(images)} images, "
          f"{checked} quoted fragments/lines checked")
    if problems:
        for p in problems:
            print("  " + p)
    if moved:
        # last so that it is the line a reader of a failed CI job actually sees
        verdict = (f"FAIL: {len(moved)} image(s) scanned here are not the build "
                   f"verification/*.md describes -- the samples moved, so this run is not "
                   f"checking the answer key's own bytes")
        if problems:
            verdict += (f", and the {len(problems)} quote problem(s) above cannot be "
                        f"judged until it is")
        print(verdict)
        return 1
    if problems:
        print(f"FAIL: {len(problems)} stale quote(s) in the prose")
        return 1
    print("ok: every quoted number is what the tool prints today")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
