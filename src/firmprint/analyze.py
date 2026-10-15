"""Pipeline: container -> vector table -> SoC candidates -> carving -> capstone.

`analyze()` returns a report dict that is safe to publish: it contains offsets
and byte snippets, never whole-buffer dumps, and it states which engines ran and
which did not.
"""
from __future__ import annotations

import platform
import time
from pathlib import Path

from . import carve, container, decode, evidence, vectors
from .socdb import Soc, load_soc

TOOL = "firmprint"
VERSION = "0.1.0"
SCHEMA = "firmprint-report/1"


def _soc_for_words(image, socs: dict[str, Soc], exclude) -> dict[str, dict]:
    """What each installed map can see in this image: blocks and distinct addresses."""
    return {name: carve.explained_constants(image, soc, exclude_ranges=exclude)
            for name, soc in socs.items()}


def analyze(path: str, soc_name: str | None = None, base: int | None = None,
            data_dir: Path | None = None, budget: int | None = None, full: bool = False,
            skip_code: bool = False) -> dict:
    t0 = time.time()
    raw = Path(path).read_bytes()
    image = container.load(path, base=base)

    tables = vectors.scan_tables(image)
    best_table = max(tables, key=lambda f: f.confidence) if tables else None

    socs = {soc_name: load_soc((data_dir or Path(__file__).with_name("data")) / f"{soc_name}.json")} \
        if soc_name else _load_all(data_dir)
    if not socs:
        raise SystemExit("no SoC databases found — run: firmprint socdb list / firmprint socdb add")

    exclude = [(s.vaddr, s.end) for s in image.segments]        # literal pointers into the image
    explained = _soc_for_words(image, socs, exclude)
    ranked = vectors.rank_socs(image, socs, best_table, explained)

    if soc_name and soc_name in socs:
        chosen = socs[soc_name]
    elif ranked:
        chosen = socs[ranked[0].subject]
    else:
        chosen = next(iter(socs.values()))
    counts, hits, cstats = carve.carve_bases(image, chosen, exclude_ranges=exclude)
    per = carve.peripheral_usage(counts, hits)

    findings: list[evidence.Finding] = list(tables)
    findings.extend(ranked)
    findings.extend(carve.usage_findings(per, chosen))
    for fn in (carve.entropy_finding(image), carve.strings_finding(image)):
        if fn:
            findings.append(fn)

    decode_stats = {"engine": None,
                    "reason": "absent" if not decode.available() else
                              ("requested" if skip_code else None)}
    if not skip_code and decode.available():
        findings, dstats = _with_decode(findings, image, chosen, budget, full, socs)
        decode_stats = dstats
        if decode_stats.get("engine") is None:      # capstone import broke mid-run
            decode_stats["reason"] = "absent"

    violations = evidence.validate(findings)
    return {
        "schema": SCHEMA,
        "meta": {
            "tool": TOOL,
            "version": VERSION,
            "elapsed_sec": round(time.time() - t0, 2),
            "python": f"{platform.python_version()} / {platform.system().lower()}",
            "file": {"path": str(path), "size": len(raw), "sha256": evidence.sha256_file(raw)},
            "container": image.to_dict(),
            "soc": chosen.summary(),
            "soc_scan": {"databases_considered": sorted(socs),
                         "per_database": {k: {"blocks": len(v["blocks"]),
                                              "device_constants": len(v["addrs"])}
                                          for k, v in explained.items()}},
            "engines": {"container": "container/1", "vectors": "vectors/1",
                        "carve": "carve/1", "decode": decode_stats.get("engine")},
            "decode": decode_stats,
            "carve_stats": cstats,
        },
        "findings": [f.to_dict(fid) for fid, f in evidence.iter_numbered(findings)],
        "contract": {"strict": True, "violations": violations,
                     "note": "a violation means a confident claim lost its evidence; "
                             "treat the report as untrustworthy until it is empty"},
    }


def _with_decode(findings, image, chosen, budget, full, socs):
    extra, stats = decode.decode_code(image, chosen, budget=budget or decode.DEFAULT_CODE_BUDGET,
                                      full=full, others=socs)
    merged = findings + extra
    return merged, stats


def _load_all(data_dir: Path | None) -> dict[str, Soc]:
    from .socdb import load_all
    return load_all(data_dir)


def to_markdown(report: dict) -> str:
    """Human-facing summary.  Keeps the evidence visible so a reader can re-check it."""
    meta = report["meta"]
    lines = [f"# firmprint report — `{Path(meta['file']['path']).name}`", ""]
    lines.append(f"- file: {meta['file']['size']:,} bytes, sha256 `{meta['file']['sha256'][:16]}…`")
    lines.append(f"- container: **{meta['container']['format']}**, arch {meta['container']['arch']}, "
                 f"{len(meta['container']['segments'])} segment(s)")
    soc = meta["soc"]
    lines.append(f"- matched SoC: **{soc['device']}** ({soc['family']}, {soc['core']}), "
                 f"{soc['peripherals']} mapped peripherals, db from "
                 f"{soc['provenance']['source_repo']}@`{str(soc['provenance']['header_sha256'])[:12]}`")
    lines.append(f"- engines: {', '.join(v for v in meta['engines'].values() if v)}")
    if meta["decode"].get("engine") is None:
        reason = {"absent": "capstone not installed",
                  "requested": "instruction decoding skipped by request"}.get(
            meta["decode"].get("reason"), "instruction decoding did not run")
        lines.append(f"- note: {reason} → register-level access not attempted "
                     "(address carving only)")
    lines += ["", "| finding | subject | conf | summary |", "|---|---|---|---|"]
    for f in report["findings"][:40]:
        lines.append(f"| `{f['kind']}` | {f['subject']} | {f['confidence']:.2f} | {f['summary'][:150]} |")
    lines.append("")
    lines.append(f"contract: {len(report['contract']['violations'])} violation(s)")
    return "\n".join(lines) + "\n"
