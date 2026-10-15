#!/usr/bin/env python3
"""Generate firmprint SoC memory-map databases from vendor CMSIS headers.

Why generated instead of hand-written: a hand-typed peripheral map is a
credibility liability — one wrong base address and every register hit in the
report is noise.  CMSIS device headers are the same files the compiler and
debug probes use, so the ground truth is pulled straight from the vendor.

Every generated database records the source repo, the path inside it, and the
sha256 of the exact header bytes it parsed, so a reader can re-verify it:

    python tools/gen_socdb.py fetch --family f4 --device stm32f427xx
    python tools/gen_socdb.py build --family f4 --device stm32f427xx

Raw headers are cached under ./socdb-src/ and the JSON lands in
src/firmprint/data/.  The fetch step talks to api.github.com with the
``Accept: application/vnd.github.raw+json`` media type because GitHub's
contents API returns an empty body for files over 1 MB (CMSIS headers are
~2 MB).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "socdb-src"
OUT = ROOT / "src" / "firmprint" / "data"

# device header -> (github repo, path in repo)
KNOWN = {
    ("h7", "stm32h743xx"): ("STMicroelectronics/cmsis-device-h7", "Include/stm32h743xx.h"),
    ("h7", "stm32h750xx"): ("STMicroelectronics/cmsis-device-h7", "Include/stm32h750xx.h"),
    ("f4", "stm32f427xx"): ("STMicroelectronics/cmsis-device-f4", "Include/stm32f427xx.h"),
    ("f4", "stm32f407xx"): ("STMicroelectronics/cmsis-device-f4", "Include/stm32f407xx.h"),
    ("f7", "stm32f765xx"): ("STMicroelectronics/cmsis-device-f7", "Include/stm32f765xx.h"),
    ("l4", "stm32l476xx"): ("STMicroelectronics/cmsis-device-l4", "Include/stm32l476xx.h"),
    ("g0", "stm32g071xx"): ("STMicroelectronics/cmsis-device-g0", "Include/stm32g071xx.h"),
    ("g4", "stm32g474xx"): ("STMicroelectronics/cmsis-device-g4", "Include/stm32g474xx.h"),
    ("h5", "stm32h503xx"): ("STMicroelectronics/cmsis-device-h5", "Include/stm32h503xx.h"),
    ("l5", "stm32l552xx"): ("STMicroelectronics/cmsis-device-l5", "Include/stm32l552xx.h"),
    ("u5", "stm32u5a9xx"): ("STMicroelectronics/cmsis-device-u5", "Include/stm32u5a9xx.h"),
    ("wb", "stm32wb55xx"): ("STMicroelectronics/cmsis-device-wb", "Include/stm32wb55xx.h"),
    ("wl", "stm32wle5xx"): ("STMicroelectronics/cmsis-device-wl", "Include/stm32wle5xx.h"),
}

DEFINE_RE = re.compile(r"^#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\s*(?:/\*.*\*/)?\s*$")
NUMBER_RE = re.compile(r"\(?\s*(0[xX][0-9a-fA-F]+)(?:UL|U|L)?\s*\)?")
IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


def fetch(repo: str, path: str, dest: Path) -> None:
    """Download a header through the contents API; media type avoids the >1MB empty-body bug."""
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github.raw+json",
        "User-Agent": "firmprint-socdb-gen",
    })
    print(f"fetching {url}", file=sys.stderr)
    body = urllib.request.urlopen(req, timeout=180).read()
    if len(body) < 1000:
        raise SystemExit(f"response too small ({len(body)} bytes) — repo/path wrong or rate-limited")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(body)
    print(f"wrote {dest} ({len(body)} bytes)", file=sys.stderr)


def parse_defines(text: str) -> dict[str, str]:
    """name -> raw right-hand-side expression, later wins on duplicates."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = DEFINE_RE.match(line.strip())
        if not m:
            continue
        name, rhs = m.group(1), m.group(2)
        rhs = rhs.split("//")[0].strip()
        # keep parenthesised constant expressions, drop macro-function bodies
        paren_const = (rhs.startswith("(") and
                       re.fullmatch(r"[\w\s\(\)+\-\*/<>|&xX0-9A-FUL]+", rhs.strip()))
        if not rhs or (rhs.startswith(("(", "\\", "}")) and not paren_const):
            continue
        if " " in rhs and not re.fullmatch(r"0x[0-9A-Fa-f]+UL?|\([A-Za-z_0-9 ()+\-*/|<>]+\)|[A-Za-z_][A-Za-z0-9_]*",
                                           rhs.strip()):
            stripped = re.sub(r"/\*.*?\*/", "", rhs).strip()
            if not re.fullmatch(r"[\w\s\(\)+\-\*/<>|]+", stripped):
                continue
            rhs = stripped
        out[name] = rhs.strip()
    return out


def resolve(defines: dict[str, str], name: str, _depth: int = 0) -> int | None:
    """Evaluate a #define expression of literals, +, () and other defines."""
    if _depth > 40:
        return None
    rhs = defines.get(name)
    if rhs is None:
        return None
    return eval_expr(defines, rhs, _depth)


def eval_expr(defines: dict[str, str], expr: str, depth: int) -> int | None:
    expr = expr.strip()
    if expr.startswith("(") and expr.endswith(")"):
        inner = expr[1:-1]
        if inner.count("(") == inner.count(")"):
            return eval_expr(defines, inner, depth)
    m = re.fullmatch(r"0x[0-9a-fA-F]+(?:UL|U|L)?", expr)
    if m:
        return int(expr.rstrip("UL"), 16) if expr[-1] in "UL" else int(expr, 16)
    m = re.fullmatch(r"0x[0-9a-fA-F]+(UL|U|L)", expr)
    if m:
        return int(expr[:-len(m.group(1))], 16)
    m = re.fullmatch(r"\d+", expr)
    if m:
        return int(expr)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
        return resolve(defines, expr, depth + 1)
    # split on the lowest-precedence '+' / '|' at depth 0
    for op in ("+", "|"):
        parts = split_top(expr, op)
        if len(parts) > 1:
            vals = [eval_expr(defines, p, depth) for p in parts]
            if any(v is None for v in vals):
                return None
            acc = vals[0]
            for v in vals[1:]:
                acc = acc + v if op == "+" else acc | v
            return acc
    return None


def split_top(expr: str, op: str) -> list[str]:
    parts, buf, depth = [], [], 0
    i = 0
    while i < len(expr):
        c = expr[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if depth == 0 and expr.startswith(op, i):
            parts.append("".join(buf))
            buf = []
            i += len(op)
            continue
        buf.append(c)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


FIELD_RE = re.compile(
    r"^\s*(?P<acc>__IO|__IM|__I)?\s*(?:const\s+|volatile\s+)*"
    r"(?P<type>uint32_t|uint16_t|uint8_t|int32_t)\s+(?P<name>\w+)\s*(?:\[\s*(?P<dim>\d+)U?\s*\])?\s*;",
    re.M)
OFFSET_RE = re.compile(r"Address offset:\s*(0x[0-9A-Fa-f]+)")
STRUCT_RE = re.compile(r"typedef\s+struct\s*\{(?P<body>.*?)\}\s*(?P<name>\w+)_TypeDef\s*;", re.S)
TYPE_SIZES = {"uint32_t": 4, "int32_t": 4, "uint16_t": 2, "uint8_t": 1}


def parse_types(text: str) -> dict[str, dict[str, tuple[int, int, str]]]:
    """Peripheral struct name -> {register: (offset, size, access)} from CMSIS.

    Reserved holes (`uint32_t RESERVED3;`) are skipped; arrays keep their span so a
    scanner can match any element, e.g. GPIO AFR[2] covers 0x20 and 0x24.
    """
    out: dict[str, dict[str, tuple[int, int, str]]] = {}
    for sm in STRUCT_RE.finditer(text):
        body = sm.group("body")
        regs: dict[str, tuple[int, int, str]] = {}
        for fm in FIELD_RE.finditer(body):
            name = fm.group("name")
            if name.startswith("RESERVED") or name.startswith("_"):
                continue
            om = OFFSET_RE.search(body, fm.end(), fm.end() + 200)
            if not om:
                continue
            size = TYPE_SIZES[fm.group("type")] * int(fm.group("dim") or 1)
            access = {"__I": "r", "__IO": "rw", "__IM": "r"}[fm.group("acc") or "__IO"]
            regs[name] = (int(om.group(1), 16), size, access)
        if regs:
            out[sm.group("name")] = regs
    return out


#: the CMSIS core the header instantiates.  Read from the header's own
#: `__CM<n>_REV` define: STM32H7 is a Cortex-M7 (armv7e-M), so a lookup keyed on
#: the *family* string labelled it armv8-M, which is wrong in the first line a
#: reader checks.  The core is a fact about the silicon, not about ST's marketing.
CORE_BY_CM = {"3": "cortex-m3", "4": "cortex-m4", "7": "cortex-m7", "23": "cortex-m23",
              "33": "cortex-m33", "35": "cortex-m35", "55": "cortex-m55"}


def detect_core(text: str) -> str:
    hits = sorted({m.group(1) for m in re.finditer(r"#\s*define\s+__CM(\d+)_REV", text)})
    if len(hits) == 1:
        return CORE_BY_CM.get(hits[0], f"cmsis-core-{hits[0]}")
    # ambiguous (a header that pulls in two core headers) or absent: say so instead
    # of picking one, because the report prints this value as a fact
    return ",".join(f"unknown({h})" for h in hits) or "unknown"


def build(family: str, device: str, header: Path, repo: str, path: str) -> dict:
    text = header.read_text(encoding="utf8", errors="replace")
    defines = parse_defines(text)

    peripherals: dict[str, dict] = {}
    dropped_low: list[tuple[str, int]] = []
    for name, rhs in sorted(defines.items()):
        if not name.endswith("_BASE") or name.endswith("_PERIPH_BASE"):
            continue
        if name == "PERIPH_BASE":
            continue
        value = eval_expr(defines, rhs, 0)
        if value is None or not (0 <= value <= 0xFFFFFFFF):
            continue
        # ST's USB core (and a few other drivers) reuse the `_BASE` suffix for
        # *struct-relative* offsets: `#define USB_OTG_GLOBAL_BASE 0x000UL`.
        # Treating those as addresses makes every NULL word in a firmware look
        # like a reference to a peripheral, so anything below 0x0010_0000 is
        # dropped.  The trade: H7 ITCM (0x0000_0000) is lost with them.
        if value < 0x0010_0000:
            dropped_low.append((name[:-5], value))
            continue
        peripherals[name[:-5]] = {"base": value, "expr": re.sub(r"\s+", " ", rhs)}
    if dropped_low:
        print(f"note: dropped {len(dropped_low)} sub-1MB `_BASE` define(s) "
              f"(struct-relative offsets, e.g. {dropped_low[0][0]})")

    # register layout comes from the CMSIS peripheral structs, not the datasheet PDF:
    # every field carries an explicit `Address offset: 0x1C` comment, and
    # `#define GPIOA ((GPIO_TypeDef *) GPIOA_BASE)` binds instance -> struct type.
    types = parse_types(text)
    instance_type: dict[str, str] = {}
    for _name, rhs in defines.items():
        m = re.fullmatch(r"\(\s*\(\s*(\w+)_TypeDef\s*\*\s*\)\s*(\w+)_BASE\s*\)", re.sub(r"\s+", " ", rhs.strip()))
        if m and m.group(2) in peripherals:
            instance_type[m.group(2)] = m.group(1)

    for pname, entry in peripherals.items():
        tname = instance_type.get(pname)
        if tname:
            entry["type"] = tname
            regs = types.get(tname, {})
            entry["size"] = max((o + s for (o, s, _a) in regs.values()), default=0) or 4

    # memory regions (flash / sram / backup sram) for vector-table scoring.
    # `peripherals` keys already have `_BASE` stripped, so try both spellings.
    regions = {}
    for key in ("D1_AXIFLASH", "D1_AXIFLASH_BASE", "FLASH_BANK1", "FLASH", "FLASH_BASE",
                "D1_DTCMRAM", "D1_AXISRAM", "D2_AXISRAM", "D2_AHBSRAM",
                "SRAM", "SRAM_BASE", "SRAM0_BASE", "SRAM1_BASE", "SRAM2_BASE",
                "BKPSRAM", "BKPSRAM_BASE", "D3_SRAM", "D3_BKPSRAM", "OCRAM", "RAM"):
        k = key[:-5] if key.endswith("_BASE") else key
        if key in peripherals:
            regions[key] = peripherals[key]["base"]
        elif k in peripherals:
            regions.setdefault(k, peripherals[k]["base"])

    sha256 = hashlib.sha256(header.read_bytes()).hexdigest()
    return {
        "schema": "firmprint-socdb/1",
        "family": family,
        "device": device,
        "core": detect_core(text),
        "provenance": {
            "generator": "tools/gen_socdb.py",
            "source_repo": repo,
            "source_path": path,
            "header_sha256": sha256,
            "header_bytes": header.stat().st_size,
            "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dropped_low_base_defines": len(dropped_low),
        },
        "memory_regions": regions,
        "peripherals": peripherals,
        "types": types,
        "instance_type": instance_type,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="download a CMSIS header into socdb-src/")
    f.add_argument("--family", required=True)
    f.add_argument("--device", required=True)

    b = sub.add_parser("build", help="turn a cached header into a JSON database")
    b.add_argument("--family", required=True)
    b.add_argument("--device", required=True)
    b.add_argument("--header", type=Path)

    a = sub.add_parser("list", help="known devices")
    a.add_argument("--all", action="store_true")

    args = ap.parse_args()
    if args.cmd == "list":
        for (fam, dev), (repo, path) in sorted(KNOWN.items()):
            print(f"{fam:3} {dev:16} {repo}:{path}")
        return 0

    key = (args.family, args.device)
    if key not in KNOWN and not getattr(args, "header", None):
        raise SystemExit(f"unknown {args.family}/{args.device}; known: " +
                         ", ".join(f"{d} ({f})" for f, d in KNOWN))
    if key in KNOWN:
        repo, path = KNOWN[key]
        header = CACHE / f"{args.device}.h"
    else:  # explicit --header for devices not in KNOWN
        repo, path, header = "local", str(args.header), args.header

    if args.cmd == "fetch":
        fetch(repo, path, header)
        return 0

    if not header.exists():
        raise SystemExit(f"cached header missing: {header} — run: fetch --family {args.family} --device {args.device}")
    db = build(args.family, args.device, header, repo, path)
    OUT.mkdir(parents=True, exist_ok=True)
    dest = OUT / f"{args.device}.json"
    dest.write_text(json.dumps(db, separators=(",", ":")) + "\n", encoding="utf8")
    print(f"{dest.name}: {len(db['peripherals'])} peripherals, "
          f"{len(db['types'])} struct types, {sum(len(t) for t in db['types'].values())} registers, "
          f"sha256={db['provenance']['header_sha256'][:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
