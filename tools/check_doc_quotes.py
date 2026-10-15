#!/usr/bin/env python3
"""Check that every number and report line quoted in the prose is what the tool prints.

The README and `docs/case-*.md` paste real output.  Prose drifts: a confidence gets
rewritten to three decimals, a summary gets paraphrased, a count changes because a
heuristic was fixed.  Each of those is a documentation bug of the worst kind, because the
whole argument of this project is that a claim comes with its evidence.

So the quotes are machine-checked, in two ways:

  * a ```json fragment must be a *subset* of some real finding (every key it shows has to
    carry that finding's value, strings matched as substrings because the docs elide);
  * a text-shaped `kind subject conf` line, and a header line (`match`, `candidates`,
    `decoded`, `contract`, `engines`, `file`, `container`), must match a real run.

Usage:
    python tools/check_doc_quotes.py            # needs samples/ fetched
    python tools/check_doc_quotes.py --list     # show what was checked
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if (ROOT / "src").exists():                                   # run from a checkout
    sys.path.insert(0, str(ROOT / "src"))

from firmprint import cli, decode  # noqa: E402

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


def blocks(text: str) -> list[tuple[str, str]]:
    """(fence language, body) for every fenced block; the language is on the fence line."""
    return [(lang.strip(), body) for lang, body in re.findall(r"```([^\n]*)\n(.*?)```", text, re.S)]


def subset(frag: dict, real: dict) -> bool:
    """Every key the fragment shows must carry the real value (strings as substrings)."""
    for key, want in frag.items():
        got = real.get(key)
        if isinstance(want, str):
            if not isinstance(got, str) or want not in got:
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


def run_all(images: list[Path]) -> tuple[list[dict], list[str]]:
    """Return (every finding from every image, every plain-text line they printed)."""
    findings: list[dict] = []
    lines: list[str] = []
    for path in images:
        for fmt in ("json", "text"):
            buf = io.StringIO()
            args = ["scan", str(path), "--format", fmt, "--max-findings", "10000"]
            if not decode.available():
                args.append("--no-code")
            with contextlib.redirect_stdout(buf):
                rc = cli.main(args)
            if rc != 0:
                raise SystemExit(f"scan failed on {path.name} ({rc}): {buf.getvalue()[:200]}")
            if fmt == "json":
                findings.extend(json.loads(buf.getvalue())["findings"])
            else:
                lines.extend(buf.getvalue().splitlines())
    return findings, lines


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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true", help="print each quote that was checked")
    a = ap.parse_args()

    images = sorted(p for p in (ROOT / "samples").glob("*/*")
                    if p.suffix in (".bin", ".elf") and p.is_file())
    if not images:
        print("no samples: run `python tools/get_sample.py --all` first "
              "(the dependency-free CI job does not need this check)")
        return 0

    findings, lines = run_all(images)
    live_text = flat("\n".join(lines))
    # (kind, subject, conf@2dp) -> the summaries the tool printed for that triple
    live_pairs: dict[tuple[str, str, str], list[str]] = {}
    for line in lines:
        s = line.strip()
        if m := FINDING.match(s):
            live_pairs.setdefault(m.groups()[:3], []).append(s[m.end():].strip())
    # and the same triples from the JSON, where nothing is truncated at the column:
    # a doc may quote further into a summary than the text table ever printed
    live_summaries: dict[tuple[str, str, str], list[str]] = {}
    for f in findings:
        key = (f["kind"], str(f["subject"])[:19], f"{f['confidence']:.2f}")
        live_summaries.setdefault(key, []).append(f["summary"])
    problems: list[str] = []
    checked = 0

    for md in DOCS:
        rel = md.relative_to(ROOT)
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
                if not any(subset(item, f) for f in findings):
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
                    if triple not in live_pairs:
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
                    quoted_tail = flat(" ".join(tail)).split("…")[0].split(" ...")[0].strip()
                    if quoted_tail and not any(
                            quoted_tail in flat(t) or flat(t).startswith(quoted_tail)
                            for t in live_pairs[triple]) and not any(
                            quoted_tail in flat(sm) for sm in live_summaries.get(triple, [])):
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
                    head = flat(s.split("…")[0].split(" ...")[0].rstrip(". "))
                    checked += 1
                    if a.list:
                        print(f"  quote  {rel}: {head[:70]}")
                    if head not in live_text:
                        problems.append(f"{rel}: header line not printed by any real run: {head[:70]}")

    print(f"doc quotes: {len(findings)} findings from {len(images)} images, "
          f"{checked} quoted fragments/lines checked")
    if problems:
        for p in problems:
            print("  " + p)
        print(f"FAIL: {len(problems)} stale quote(s) in the prose")
        return 1
    print("ok: every quoted number is what the tool prints today")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
