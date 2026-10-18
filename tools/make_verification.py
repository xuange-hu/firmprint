#!/usr/bin/env python3
"""Regenerate verification/*.md from real runs of this repository's code.

Nothing in those files is typed by hand: every number, table row and sha256 is
produced by running `firmprint.analyze` against the samples fetched by
`tools/get_sample.py`.  Change an engine, re-run this, and the claims move — which
is the point.

    python tools/make_verification.py            # both boards
    python tools/make_verification.py openmv3    # one board

Two boards are on purpose.  OpenMV2 is an STM32F427 and OpenMV3 is an STM32F765,
and their CMSIS peripheral windows overlap almost completely, so the pair is the
honest test of whether a memory-map ranking can tell a part from its own family.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

# `get_sample` is imported, not duplicated: the document has to state the release and the
# archive digest the fetcher *actually* pins, so a reader can re-fetch exactly these bytes.
import get_sample as fetch  # noqa: E402

from firmprint.analyze import analyze  # noqa: E402
from firmprint.container import load  # noqa: E402
from firmprint.verify import (  # noqa: E402
    _render,
    compare,
    detected_peripherals,
    symbol_oracle,
)

#: board -> (sample dir, vendor part, true application link address, doc name)
BOARDS = {
    "openmv2": (ROOT / "samples" / "openmv2", "STM32F427VGT6", 0x0801_0000, "openmv2.md"),
    "openmv3": (ROOT / "samples" / "openmv3", "STM32F765VGT6", 0x0802_0000, "openmv3.md"),
}
BANNER = re.compile(rb"(OPENMV\d+ with STM32\w+)")

#: cheap per-board answers, filled by `_lead_of`: how many device constants the
#: winning map explains that no other installed map can see.  The two boards are
#: quoted against each other, so the number has to come from a real run.
_LEADS: dict[str, int] = {}


def _lead_of(board: str) -> int:
    if board not in _LEADS:
        rep = analyze(str(BOARDS[board][0] / "firmware.bin"), skip_code=True)
        top = next(f for f in rep["findings"] if f["kind"] == "soc.candidate")
        _LEADS[board] = top["metrics"]["exclusive_constants"]
    return _LEADS[board]


def run(path: Path, **kw):
    t = time.time()
    return analyze(str(path), **kw), round(time.time() - t, 2)


def _banner(path: Path) -> str | None:
    """The vendor's own build banner, if the image carries one.

    This is the cheapest answer key in the world and the least interesting: the ELF
    is not a dump.  It is reported because it lets a reader confirm the part name
    without trusting either the symbol oracle or the memory-map ranking.
    """
    m = BANNER.search(path.read_bytes())
    return m.group(1).decode() if m else None


def _score_line(rep: dict) -> str:
    """`part=constants/blocks(lead, blind)` for every installed map, ranked."""
    rows = [f for f in rep["findings"] if f["kind"] == "soc.candidate"]
    return ", ".join(f"{r['subject']}={r['metrics']['constants_explained']} constants/"
                     f"{r['metrics']['blocks_explained']} blocks "
                     f"(exclusive {r['metrics']['exclusive_constants']}, "
                     f"blind {r['metrics']['blind_constants']}, conf {r['confidence']})"
                     for r in rows)


def _tables(rep: dict) -> list[dict]:
    return [f for f in rep["findings"] if f["kind"] == "cortex-m.vector_table"]


def source_line() -> str:
    """Where the bytes came from, named by the digest the fetcher pins for the archive.

    Refuses rather than prints a blank: an answer key that does not say which build it
    describes is a list of numbers about unnamed bytes, and `verification/*.md` exists to be
    the file a skeptic opens first.
    """
    if not fetch.ASSET_SHA256:
        raise SystemExit("tools/get_sample.py pins no archive digest, so this document "
                         "could not say which build it describes -- pin it first")
    unpinned = sorted(b for b, (_p, _d, pins) in fetch.BOARDS.items() if not pins)
    if unpinned:
        raise SystemExit(f"tools/get_sample.py pins no files for {', '.join(unpinned)}; "
                         "refusing to write an answer key for bytes nothing can re-fetch")
    asset = fetch.ASSET.rsplit("/", 1)[-1]
    return (f"- source: OpenMV release `{fetch.RELEASE}`, asset `{asset}` (sha256 "
            f"`{fetch.ASSET_SHA256}`), fetched by `python tools/get_sample.py --all`")


def image_line(rep: dict, path: Path) -> str:
    """One scanned build, named by the digest the scanner read.

    Module level, not a closure inside `build()`, because `tools/check_doc_quotes.py` parses
    exactly this line to learn which bytes the answer key describes, and a format contract
    two files share has to be testable without downloading 91 MB of firmware first.

    All three views of a board get a line, not just the ELF: a moved `firmware.bin` is exactly
    as misleading as a moved `firmware.elf`, and the docs quote both.
    """
    m = rep["meta"]["file"]
    return f"- image: `{path.name}`, {m['size']:,} bytes, sha256 `{m['sha256']}`"


def build(board: str, other_board: str) -> tuple[str, dict]:
    samples, part, true_base, _doc = BOARDS[board]
    elf, binf, merged = (samples / n for n in ("firmware.elf", "firmware.bin", "openmv.bin"))
    for f in (elf, binf, merged):
        if not f.exists():
            raise SystemExit(f"missing sample: {f}\nrun: python tools/get_sample.py "
                             f"--board {board.upper()}")

    rep_elf, t_elf = run(elf)
    rep_bin, t_bin = run(binf)
    rep_merge, t_merge = run(merged)

    modules, samples_syms = symbol_oracle(load(str(elf)).symbols)
    res = compare(rep_elf, modules)
    ORACLE_TABLE = ("| oracle module |"
                    + _render(rep_elf, res, samples_syms, str(elf)).split("| oracle module |", 1)[1])

    elf_set = set(detected_peripherals(rep_elf))
    bin_set = set(detected_peripherals(rep_bin))
    top_bin = next(f for f in rep_bin["findings"] if f["kind"] == "soc.candidate")
    gap = next((f for f in rep_elf["findings"] if f["kind"] == "soc.coverage"), None)
    banner = _banner(elf)
    soc = rep_elf["meta"]["soc"]
    inferred = load(str(binf)).segments[0].vaddr

    L = [
        f"# Verification: {board} ({part})",
        "",
        "A reverse-engineering tool that outputs confident prose is easy to dismiss, so this",
        "repository ships an answer key instead of a promise.  Every number below was produced",
        f"by `python tools/make_verification.py {board}` against MIT-licensed OpenMV firmware —",
        "no figure is typed in by hand.",
        "",
        source_line(),
        *([image_line(rep_elf, elf), image_line(rep_bin, binf), image_line(rep_merge, merged)]
          + ["",
             "Three views of the same board: the ELF carries symbols (the oracle reads them),",
             "the raw flash image is what a confiscation bag actually contains, and the merged",
             "release image is what OpenMV ships to the device.  `tools/get_sample.py` pins all",
             "three by sha256, and the doc gate fails if the bytes on disk are not these.",
             ""]),
        f"- vendor part: **{part}**"
        + (f", confirmed by the banner string the build embedded: `{banner}`" if banner else ""),
        f"- firmprint answer: **{soc['device']}** ({soc['family']}, {soc['core']}) from "
        f"`{soc['provenance']['source_repo']}` header sha256 "
        f"`{soc['provenance']['header_sha256'][:16]}...`",
        f"- evidence-contract violations: **{len(rep_elf['contract']['violations'])}**",
        "",
        "## 1. Do the peripheral claims match reality?",
        "",
        "The oracle is the image's own symbol table: ST's Hardware Abstraction Layer links one",
        "`HAL_<MODULE>_*` family per driven peripheral, so the linker says which peripherals have",
        "driver code present.  firmprint never sees that mapping as input — it reads 32-bit",
        "constants and Thumb-2 instructions and derives blocks from addresses.",
        "",
        f"- instructions decoded: {rep_elf['meta']['decode']['instructions']:,} "
        f"({rep_elf['meta']['decode']['coverage']:.0%} of code, "
        f"{rep_elf['meta']['decode']['functions']} functions)",
        f"- driver-linked modules: **{res['oracle_modules']}**, confirmed by firmprint: "
        f"**{res['confirmed']}/{res['oracle_modules']}** (recall {res['recall_over_drivers']:.0%})",
        "",
        ORACLE_TABLE,
        "",
        "A module counts as confirmed when *any* of its blocks shows up: that is the lenient",
        "reading of recall.  It answers \"did the tool find driver-bearing hardware\", not \"did",
        "it find every instance\", and per-block precision is not measurable against this oracle,",
        "because a linked-but-unused driver and a direct register write look the same to it.",
        "",
        "## 2. Does it work with the metadata removed?",
        "",
        "`firmware.bin` is the same flash with the ELF wrapper stripped: no section headers, no",
        "program headers, no symbol table.  The instruction engine cannot name functions and the",
        "oracle is unavailable, so what survives is the part that matters for a real dump.",
        "",
        f"- inferred load base: **0x{inferred:08X}** (true application link address: "
        f"0x{true_base:08X} — the app sits above a "
        f"{(true_base - 0x0800_0000) // 1024} KB bootloader)",
        f"- matched part: **{rep_bin['meta']['soc']['device']}** — "
        + top_bin["summary"].split(";", 1)[0].strip(),
        f"- every installed map, in rank order: {_score_line(rep_bin)}",
        f"- peripheral blocks reported: {len(bin_set)} of the {len(elf_set)} the ELF run found",
        f"- byte-identical answer without metadata: "
        f"**{'yes' if bin_set == elf_set else f'{len(elf_set & bin_set)}/{len(elf_set)} blocks'}**",
        "",
    ]
    only_elf, only_bin = sorted(elf_set - bin_set), sorted(bin_set - elf_set)
    if only_elf or only_bin:
        L += [f"- differences: ELF-only {only_elf or 'none'}; BIN-only {only_bin or 'none'}", "",
              "Those come from the decode byte budget, not from disagreement about the chip: the",
              "ELF run names functions and can spend its budget on real bodies, the raw run cannot."]
    L += [
        "",
        "## 3. Two vector tables in one file",
        "",
        "`openmv.bin` is the merged release image: a bootloader followed by the application.",
        "Both halves carry a table, so a tool that reports one base for the file is wrong about",
        "one of them.",
        "",
        "| image | table | confidence | live handlers | slots | initial MSP | reset |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in (rep_elf, rep_bin, rep_merge):
        for t in _tables(f):
            m = t["metrics"]
            L.append(f"| {Path(f['meta']['file']['path']).name} | {t['subject']} | "
                     f"{t['confidence']:.3f} | {m['n_live']} | {m['n_scanned']} | "
                     f"{m['msp']} | {m['reset']} |")
    L += [
        "",
        f"- merged image base inference: 0x{load(str(merged)).segments[0].vaddr:08X} "
        "(correct: the bootloader is at 0x08000000)",
        f"- what the inference said out loud: {load(str(merged)).notes[0]}",
        "",
        "## 4. What it refuses to claim",
        "",
        f"- it says `{soc['device']}`, not `{part}`: several part numbers share one peripheral",
        "  map, and the map is what bytes determine.  Every candidate row keeps that in `unknowns`.",
    ]
    lead = top_bin["metrics"]["exclusive_constants"]
    other_lead = _lead_of(other_board)
    if lead:
        L += ["- here the ranking separated the family on evidence: the winning map explains",
              f"  {lead} device constant(s) no other installed map can see.  The identical test on",
              f"  the `{other_board}` sample (verification/{other_board}.md) explains "
              f"{other_lead}, which is why",
              "  that report says so instead of naming a part on a coin flip."]
    else:
        L += ["- here no map has exclusive constants, so the report names the closest installed",
              "  map at reduced confidence and says the databases cannot separate these parts."]
    if gap:
        L += [f"- the matched map is also judged on what it misses: {gap['summary'][:200]}…",
              f"  (`soc.coverage`, confidence {gap['confidence']}, contested addresses: "
              f"{gap['metrics']['contested']})"]
    L += [
        "- carving proves a constant is present, not that code executed an access: those rows are",
        "  labelled `carve/1` and never claim a direction.  `peripheral.access` rows come only",
        "  from the capstone engine and quote instruction bytes.",
        "- register names resolve only where CMSIS gives the block a struct; an offset inside a",
        "  struct hole reports as the block base rather than an invented register.",
        "- this document is generated, and re-running the generator has to leave it byte-identical:",
        "  every number in it is a property of the image and of this tool.  Wall-clock timings and",
        "  the interpreter that produced them used to be printed here, which made \"no diff\" true",
        "  on one machine only; they are reported on stdout instead.",
        "",
        "## Reproduce",
        "",
        "```bash",
        "pip install -e .[capstone]",
        f"python tools/get_sample.py --board {board.upper()}   # MIT-licensed OpenMV firmware",
        f"python tools/make_verification.py {board}      # rewrites this file",
        "```",
        "",
    ]
    facts = {"board": board, "device": soc["device"], "vendor_part": part,
             "recall": f"{res['confirmed']}/{res['oracle_modules']}",
             "violations": len(rep_elf["contract"]["violations"]),
             "exclusive": lead, "banner": banner,
             "instructions": rep_elf["meta"]["decode"]["instructions"],
             # for the operator's terminal, never for the document: a timing says more about
             # the machine that ran the scan than about the firmware it read
             "runtimes": f"ELF {t_elf}s, raw {t_bin}s, merged {t_merge}s "
                         f"({rep_elf['meta']['python']})"}
    return "\n".join(L) + "\n", facts


def main() -> int:
    want = [a for a in sys.argv[1:] if not a.startswith("-")]
    boards = [b for b in BOARDS if not want or b in want]
    out = ROOT / "verification"
    out.mkdir(exist_ok=True)
    for b in boards:
        other = next((o for o in BOARDS if o != b), b)
        text, facts = build(b, other)
        # newline="\n" so a Windows contributor produces the same bytes as CI
        (out / BOARDS[b][3]).write_text(text, encoding="utf8", newline="\n")
        print(f"wrote verification/{BOARDS[b][3]}: {facts['device']} vs {facts['vendor_part']}, "
              f"oracle {facts['recall']}, {facts['violations']} violations, "
              f"{facts['exclusive']} exclusive constants")
        print(f"  scanned in {facts['runtimes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
