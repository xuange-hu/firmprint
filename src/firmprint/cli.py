"""firmprint command line.

    firmprint scan firmware.elf
    firmprint scan firmware.bin --base 0x08000000 --soc stm32f427xx
    firmprint scan app.hex --json report.json --md report.md
    firmprint mcp                          # serve the same analysis over stdio (MCP)
    firmprint socdb list
    firmprint build --header stm32h7a3xx.h --family h7 --device stm32h7a3xx
    firmprint verify firmware.elf          # binary findings vs. ELF symbol truth

Text output is the default; `--json`/`--md` write files so a report can be
attached to an issue or diffed between runs.
"""
from __future__ import annotations

import argparse
import struct
import sys
import textwrap
from pathlib import Path

from . import __version__
from .analyze import SCHEMA, analyze, to_markdown
from .evidence import dumps, render_json
from .socdb import DATA_DIR, available, load_soc

# How many rows the text table shows before it says "... N more finding(s)".  This is a
# documented number -- the README explains why `soc.candidate` does not appear in a plain
# `scan` -- so it lives here as a name rather than as a literal, and
# `tools/check_doc_quotes.py` prints it into the corpus it checks prose against.
DEFAULT_MAX_FINDINGS = 30


def _num(text: str) -> int:
    return int(text, 16) if text.lower().startswith(("0x", "-0x")) else int(text)


def _clip(value: str, width: int) -> str:
    """Fit `value` in `width` columns, and say so when it did not fit.

    The table used to do `value[:width - 1]`, which produced rows like
    `0 high-entropy bloc` -- a subject whose real name is `0 high-entropy block`, cut at a
    character nobody chose.  A reader cannot tell that apart from a label the tool actually
    uses, and a report whose own labels are silently wrong is exactly the kind of report this
    tool exists to refuse.  The ellipsis costs one column and makes the cut visible.
    """
    value = str(value)
    return value if len(value) <= width else value[:width - 1] + "…"


def _emit_console(report: dict, fmt: str, max_findings: int) -> None:
    if fmt == "json":
        print(dumps(report))
        return
    text = to_markdown(report) if fmt == "md" else _short(report, max_findings)
    sys.stdout.write(text)


def _short(report: dict, max_findings: int) -> str:
    meta = report["meta"]
    out = []
    soc = meta["soc"]
    dec = meta.get("decode") or {}
    out.append(f"file        {Path(meta['file']['path']).name}  "
               f"{meta['file']['size']:,} B  sha256:{meta['file']['sha256'][:16]}…")
    out.append(f"container   {meta['container']['format']}"
               f"{' / ' + str(meta['container'].get('arch')) if meta['container'].get('arch') else ''}"
               f"  {len(meta['container']['segments'])} segment(s)"
               f"  entry {meta['container'].get('entry') or '-'}")
    # A raw dump's load base is a *guess the tool made*, and the reason it made it is the
    # thing a reviewer needs: which origins were tried, which also produced a table.  It
    # lived only in the JSON, which meant `scan dump.bin` printed an inferred address
    # with the reasoning hidden -- the opposite of the promise in the README.
    notes = meta["container"].get("notes") or []
    for note in notes[:3]:
        out.append(textwrap.fill(note, width=100, initial_indent=" " * 12,
                                 subsequent_indent=" " * 12))
    if len(notes) > 3:
        # the reasoning is the point of these lines, so a header that shows three of six
        # has to say that three more exist and where they are
        out.append(f"             ... {len(notes) - 3} more note(s); --json carries "
                   f"all {len(notes)}")
    cands = [f for f in report["findings"] if f["kind"] == "soc.candidate"]
    top = cands[0] if cands else None
    if soc and top:
        # the verdict text, not just a part name: "best match" and "no installed map
        # is distinctive here" are different claims and a reader must see which one
        # the ranking actually made
        head = top["summary"].split(":", 1)[0].strip()
        flag = "? " if top["confidence"] < 0.6 else ""
        out.append(f"match       {flag}{soc['device']} ({soc['family']}, {soc['core']})"
                   f"  conf {top['confidence']:.2f}  {head}")
        out.append(f"            db {soc['provenance']['source_repo']}"
                   f"@{str(soc['provenance']['header_sha256'])[:12]}…")
    else:
        out.append("match       none")
    per = meta["soc_scan"].get("per_database") or {}
    out.append("candidates  " + (", ".join(
        f"{k}={v['device_constants']} constants/{v['blocks']} blocks"
        for k, v in sorted(per.items(), key=lambda kv: -kv[1]["device_constants"]))
        or "no database scored this image"))
    engines = ", ".join(f"{k}={v}" for k, v in meta["engines"].items() if v)
    out.append(f"engines     {engines}")
    if dec.get("engine"):
        out.append(f"decoded     {dec['instructions']:,} instructions, "
                   f"{dec.get('functions', 0)} function(s), coverage {dec['coverage']:.0%}")
    else:
        why = {"absent": "install capstone for register-level direction",
               "requested": "--no-code was given"}.get(dec.get("reason"), "engine did not run")
        out.append(f"decoded     skipped ({why})")
    out.append(f"contract    {len(report['contract']['violations'])} violation(s)"
               + ("" if not report["contract"]["violations"] else "  <-- DO NOT TRUST THIS REPORT"))
    out.append("")
    out.append(f"{'kind':<24}{'subject':<20}{'conf':>5}  summary")
    out.append("-" * 100)
    for f in report["findings"][:max_findings]:
        out.append(f"{_clip(f['kind'], 23):<24}{_clip(f['subject'], 19):<20}"
                   f"{f['confidence']:>5.2f}  {_clip(f['summary'], 96)}")
    left = len(report["findings"]) - max_findings
    if left > 0:
        out.append(f"... {left} more finding(s): use --max-findings or --json")
    viols = report["contract"]["violations"]
    for v in viols[:8]:
        out.append(f"VIOLATION   {v}")
    if len(viols) > 8:
        # the count line above already gives the total.  Deliberately not prefixed with
        # `VIOLATION`: a note that a list was cut is not itself a violation, and
        # `grep -c VIOLATION` has to keep counting only violations.
        out.append(f"... {len(viols) - 8} more violation(s); --json lists all {len(viols)}")
    out.append("")
    return "\n".join(out) + "\n"


def cmd_scan(a: argparse.Namespace) -> int:
    report = analyze(a.file, soc_name=a.soc, base=a.base, data_dir=Path(a.data_dir) if a.data_dir else None,
                     budget=a.budget, full=a.full, skip_code=a.no_code)
    _emit_console(report, a.format, a.max_findings)
    if a.json:
        Path(a.json).write_text(render_json(report), encoding="utf8")
        print(f"wrote {a.json}")
    if a.md:
        Path(a.md).write_text(to_markdown(report), encoding="utf8")
        print(f"wrote {a.md}")
    return 1 if report["contract"]["violations"] and a.strict else 0


def cmd_socdb(a: argparse.Namespace) -> int:
    d = Path(a.data_dir) if a.data_dir else DATA_DIR
    if a.socdb == "list":
        names = available(d)
        if not names:
            print(f"no databases in {d}")
            return 1
        for n in names:
            soc = load_soc(n, data_dir=d)
            s = soc.summary()
            print(f"{n:<22} {s['family']:<4} {s['core']:<11} "
                  f"{s['peripherals']:>4} blocks  {s['struct_types']:>3} structs  "
                  f"{str(s['provenance'].get('header_sha256'))[:12]}…")
        return 0
    if a.socdb == "show":
        if not a.name:
            print("usage: firmprint socdb show <device>   (`firmprint socdb list` for names)",
                  file=sys.stderr)
            return 2
        soc = load_soc(a.name, data_dir=d)
        print(dumps(soc.summary()))
        blocks = sorted(soc.peripherals)
        for name in blocks[:a.limit]:
            e = soc.peripherals[name]
            print(f"  {name:<22} 0x{e['base']:08X}  {e.get('type') or '-'}")
        if len(blocks) > a.limit:
            print(f"  ... {len(blocks) - a.limit} more block(s) of {len(blocks)}; "
                  f"--limit raises the cap")
        return 0
    return 2


def _generator_script() -> Path | None:
    """tools/gen_socdb.py inside a firmprint checkout, or None if there is no checkout.

    This used to be `Path(__file__).resolve().parents[2] / "tools" / "gen_socdb.py"`.
    That depth is the repository root only when the package is an editable install; in
    a wheel it lands above site-packages, and `firmprint build` then executed whatever
    `tools/gen_socdb.py` an unrelated project happened to have put there.  Requiring
    the checkout's own `pyproject.toml` beside `tools/` makes "this is the project
    root" a test of the thing rather than a guess from a directory depth.
    """
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "tools" / "gen_socdb.py"
        if candidate.exists() and (parent / "pyproject.toml").exists():
            return candidate
    return None


def cmd_build(a: argparse.Namespace) -> int:
    """Generate a database from a local CMSIS header (no network, no guesswork).

    The generator lives in `tools/gen_socdb.py` in a git checkout; an installed
    wheel ships pre-built databases, so say so plainly instead of half-working.
    """
    import importlib.util

    script = _generator_script()
    if script is None:
        print("generator not found: `firmprint build` needs the repository checkout "
              "(tools/gen_socdb.py beside pyproject.toml)\n"
              "an installed wheel ships pre-built databases and does not include the "
              "generator -- clone the repository to build from your own CMSIS headers",
              file=sys.stderr)
        return 2
    spec = importlib.util.spec_from_file_location("gen_socdb", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    header = Path(a.header)
    if not header.exists():
        print(f"no such header: {header}", file=sys.stderr)
        return 2
    db = mod.build(a.family, a.device, header, repo="local", path=str(header))
    out = Path(a.out) if a.out else (Path(a.data_dir) if a.data_dir else DATA_DIR)
    out.mkdir(parents=True, exist_ok=True)
    dest = out / f"{a.device}.json"
    dest.write_text(dumps(db, indent=1) + "\n", encoding="utf8")
    print(f"{dest}: {len(db['peripherals'])} peripheral blocks, "
          f"{len(db['types'])} register structs, "
          f"{sum(len(v) for v in db['types'].values())} register offsets, "
          f"header sha256 {db['provenance']['header_sha256'][:16]}…")
    return 0


def cmd_mcp(a: argparse.Namespace) -> int:
    from .mcp_server import main as mcp_main
    return mcp_main(["--self-test"] if a.self_test else [])


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf8", errors="replace")     # Windows cp936 safety
    except Exception:                                                  # noqa: BLE001 - cosmetic
        pass
    ap = argparse.ArgumentParser(
        prog="firmprint",
        description="Evidence-first firmware identification. Every claim carries the "
                    "offset and bytes that produced it; the report says what it could not prove.")
    ap.add_argument("--version", action="version", version=f"firmprint {__version__} ({SCHEMA})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="analyse a firmware image")
    s.add_argument("file")
    s.add_argument("--soc", help="force a database instead of ranking candidates")
    s.add_argument("--base", type=_num, help="load address for raw dumps (e.g. 0x08000000)")
    s.add_argument("--budget", type=_num, default=None, help="capstone byte budget")
    s.add_argument("--full", action="store_true", help="decode all code, ignore the budget")
    s.add_argument("--no-code", action="store_true", help="skip instruction decoding")
    s.add_argument("--data-dir", help="so gdb directory")
    s.add_argument("--format", choices=["text", "json", "md"], default="text")
    s.add_argument("--json", help="also write the machine-readable report")
    s.add_argument("--md", help="also write a markdown report")
    s.add_argument("--max-findings", type=int, default=DEFAULT_MAX_FINDINGS,
                   help="rows the text table shows before it says how many are left "
                        f"(default {DEFAULT_MAX_FINDINGS})")
    s.add_argument("--strict", action="store_true", help="exit non-zero on contract violations")
    s.set_defaults(fn=cmd_scan)

    o = sub.add_parser("socdb", help="inspect the installed memory-map databases")
    o.add_argument("socdb_cmd", choices=["list", "show"], metavar="socdb")
    o.add_argument("name", nargs="?", help="device name for `show`")
    o.add_argument("--data-dir")
    o.add_argument("--limit", type=int, default=40)
    o.set_defaults(fn=cmd_socdb)

    b = sub.add_parser("build", help="generate a database from a local CMSIS header")
    b.add_argument("--header", required=True)
    b.add_argument("--family", required=True)
    b.add_argument("--device", required=True)
    b.add_argument("--out")
    b.add_argument("--data-dir")
    b.set_defaults(fn=cmd_build)

    v = sub.add_parser("verify", help="score findings against the image's own symbols")
    v.add_argument("file")
    v.add_argument("--soc")
    v.add_argument("--base", type=_num, default=None, help="load base for a headerless dump")
    v.add_argument("--data-dir")
    v.add_argument("--budget", type=_num, default=None)
    v.add_argument("--full", action="store_true")
    v.add_argument("--json", help="write the machine-readable verification result")
    v.add_argument("--strict", action="store_true",
                   help="exit non-zero on contract violations (same meaning as `scan --strict`)")
    v.set_defaults(fn=None)

    m = sub.add_parser("mcp", help="serve the analysis tools over stdio (MCP, JSON-RPC 2.0)")
    m.add_argument("--self-test", action="store_true",
                   help="round-trip the protocol in memory and exit")
    m.set_defaults(fn=cmd_mcp)

    a = ap.parse_args(argv)
    if a.cmd == "socdb":
        a.socdb = a.socdb_cmd
    try:
        if a.cmd == "verify":
            from .verify import cmd_verify
            return cmd_verify(a)
        return a.fn(a)
    except (OSError, ValueError, struct.error) as exc:
        # a typo'd path or an unsupported wrapper is a usage error, not a stack trace.
        # `struct.error` belongs in that list because a wrapper that is long enough to
        # sniff but too short to finish parsing raises it from inside the loader, and the
        # reader still deserves the same one-line answer.
        subject = (getattr(a, "file", None) or getattr(a, "header", None)
                   or getattr(a, "name", None) or "input")
        print(f"error: {subject}: {exc}", file=sys.stderr)
        return 2
