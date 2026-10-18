"""Cortex-M vector table location and SoC candidate ranking.

The vector table is the strongest structural anchor in a headerless image: its
first word must be a stack pointer inside a RAM window, and every following
word must be an odd Thumb address inside a flash window.  That shape is not
something an analysis can hallucinate into existence, so it doubles as the
tie-breaker for "which chip is this".
"""
from __future__ import annotations

import struct
from collections import Counter

from .container import SP_WINDOWS, Image, Segment
from .evidence import Evidence, Finding
from .socdb import Soc

MIN_ENTRIES = 12          # fewer than this and it is data that happens to look odd
#: Consecutive non-handler slots that end the scan.  A table whose unused IRQ
#: range is longer than this is reported with a *lower bound* on its live count
#: (see `scan_stopped_early`), because stopping is what keeps .text words from
#: being counted as handlers of a 131-entry table.
MAX_GAP = 24
#: Windows a Cortex-M initial stack pointer can really live in, taken per vendor RAM
#: alias rather than as one big "looks like memory" band.  The earlier range
#: (0x1000_0000-0x4FFF_FFFF) admitted the whole peripheral space: a .rodata word like
#: 0x3958_4A1D passed as a stack pointer and the scanner then "found" a table in noise.
#: One definition, shared with the container's Cortex-M sniff (see `container.SP_WINDOWS`).
RAMISH = SP_WINDOWS
#: ARMv7-M b.3.4: the table's start must be aligned to a power-of-two >= 128 B.
MIN_ALIGN = 0x80
#: How far a handler may sit above its own table.  The reset handler is the first code
#: after the vectors, so a "table" whose entries start 200 KB above itself is a run of
#: constants in .text that happen to be odd.
MAX_CODE_AHEAD = 0x10_000
#: vendor flash windows a headerless dump's handler targets can sit in; used only to
#: *propose* origins for a raw dump, never to accept one (the shape test decides).
FLASH_LIKE = ((0x0800_0000, 0x0BFF_FFFF), (0x0000_0000, 0x001F_FFFF),
              (0x1000_0000, 0x101F_FFFF), (0x1200_0000, 0x13FF_FFFF),
              (0x3000_0000, 0x301F_FFFF), (0x9000_0000, 0x901F_FFFF))
FLASH_CAND_SPAN = 0x1_0000


def _in_ranges(addr: int, ranges) -> bool:
    return any(lo <= addr <= hi for lo, hi in ranges)


def scan_tables(image: Image, code_ranges=None, min_entries: int = MIN_ENTRIES) -> list[Finding]:
    """Locate plausible vector tables.  code_ranges narrows handler validation."""
    findings: list[Finding] = []
    if code_ranges is None:
        exec_segs = [s for s in image.segments if s.kind == "text"]
        if not exec_segs:
            # A headerless dump labels nothing as code, but "the handler targets
            # point inside this image" is still the test that matters.
            exec_segs = image.segments
        if exec_segs:
            code_ranges = (min(s.vaddr for s in exec_segs), max(s.end for s in exec_segs))
    for seg in image.segments:
        data = seg.data
        if len(data) < (min_entries + 2) * 4:
            continue
        # Whole-segment scan: the alignment + MSP pre-filters reject almost every
        # offset in O(1), so capping the search at a few KB (as earlier versions
        # did) only hid tables that were not at the start of the dump — an
        # application table sitting behind a 64 KB bootloader is the common case.
        start = (-seg.vaddr) % MIN_ALIGN          # keep the alignment test cheap
        for off in range(start, len(data) - (min_entries + 2) * 4, MIN_ALIGN):
            f = _try_table(image, seg, off, code_ranges, min_entries)
            if f:
                findings.append(f)
    return _drop_nested(findings)


def _drop_nested(findings: list[Finding]) -> list[Finding]:
    """Keep one reading per structure: a table cannot start inside another table.

    With the ITCM window accepted, any small odd integer looks like a stack pointer, so
    a run of ascending handler addresses re-validates as a "table" at every 128-byte
    step inside itself.  Reporting three tables where the image has one is how a scan
    starts to look like a slot machine, so the strongest reading of a span wins and the
    readings nested inside it are dropped.  A genuine second table (an application
    behind a bootloader, or a RAM copy) starts outside the first one's entries and is
    kept.
    """
    keep: list[Finding] = []
    for f in sorted(findings, key=lambda x: (-x.confidence, x.metrics["table_vaddr"])):
        v = int(f.metrics["table_vaddr"], 16)
        if any(int(f2.metrics["table_vaddr"], 16) < v
               < int(f2.metrics["table_vaddr"], 16) + 4 * int(f2.metrics["n_scanned"])
               for f2 in keep):
            continue
        keep.append(f)
    return sorted(keep, key=lambda x: int(x.metrics["table_vaddr"], 16))


def _try_table(image: Image, seg: Segment, off: int, code_ranges,
               min_entries: int = MIN_ENTRIES) -> Finding | None:
    data = seg.data
    try:
        sp, reset = struct.unpack_from("<II", data, off)
    except struct.error:
        return None
    if not _in_ranges(sp, RAMISH):
        return None

    # handler targets must live in executable memory, not anywhere in the image
    lo, hi = (code_ranges if code_ranges else
              (min((s.vaddr for s in image.segments), default=0),
               max((s.end for s in image.segments), default=0)))
    if not lo <= hi:                       # degenerate window: fall back to relative
        lo, hi = seg.vaddr, seg.vaddr + len(data)
    vaddr = seg.vaddr + off

    # Deliberately no "reset must be in 0x0800_0000..0x1FFF_FFFF": that window is
    # STM32's flash.  nRF52 runs from 0x0000_0000 and RP2040 from 0x1000_0000, so
    # the target is validated against *this image's* span instead of one vendor.
    if not reset & 1 or not (lo <= (reset & ~1) <= hi):
        return None
    # The reset handler is the code that follows the table, so it sits *just* above it.
    # Reading this back as a bound is what turns base inference into a measurement: a
    # dump read at 0x0800_0000 puts the real 0x0802_0000 application's reset vector
    # 128 KB above its own table, and that candidate is rejected instead of winning a
    # count of tables that only the low origin can manufacture out of .text noise.
    if not (reset & ~1) - vaddr < MAX_CODE_AHEAD:
        return None

    entries: list[int] = []
    zeros = 0
    junk = 0
    gap = 0
    stopped_early = False
    window = min(400, (len(data) - off) // 4 - 1)
    for k in range(1, window + 1):
        (v,) = struct.unpack_from("<I", data, off + k * 4)
        # a handler is code that comes *after* its own table: inside the image span is
        # not enough, because at base 0x0000_0000 that span is every small integer in
        # .rodata.  This is the test that stops a raw dump from growing five tables.
        if v & 1 and lo <= (v & ~1) <= hi and (v & ~1) >= vaddr:
            entries.append(v)
            gap = 0
        elif v == 0:
            zeros += 1                      # real boards ship zeroed unused vectors
            gap += 1
        else:
            junk += 1
            gap += 1
        if gap > MAX_GAP:                   # table is over; past it lies .text
            stopped_early = k < window
            break
    if len(entries) < min_entries:
        return None

    n_scanned = len(entries) + zeros + junk
    dupes = Counter(entries)
    unique = len(dupes)
    default_handler, default_hits = dupes.most_common(1)[0]
    # strict=False on purpose: a one-entry table legitimately has no successor
    monotone = sum(1 for a, b in zip(entries, entries[1:], strict=False) if (b & ~1) > (a & ~1))
    ratio = monotone / max(len(entries) - 1, 1)
    density = len(entries) / max(n_scanned, 1)
    score = 0.45 + 0.20 * min(len(entries) / 120, 1.0) + 0.20 * ratio + 0.15 * density
    if seg.name and "vector" in seg.name.lower():
        score = min(0.99, score + 0.10)

    style = ("zeroed unused slots" if zeros and default_hits <= 2 else
             "aliased to a default handler" if default_hits > 2 else "mixed")
    lower_bound = (f"; the scan stopped after {MAX_GAP} unused slots, so the live count is a "
                   "lower bound" if stopped_early else "")
    f = Finding(
        kind="cortex-m.vector_table",
        subject=f"table@0x{vaddr:08X}",
        confidence=round(min(score, 0.99), 3),
        summary=(f"vector table at 0x{vaddr:08X}: {len(entries)} live handlers within "
                 f"{n_scanned} scanned slots ({zeros} zeroed, {junk} non-code), initial MSP "
                 f"0x{sp:08X}, reset handler 0x{reset:08X}; {unique} distinct targets, "
                 f"unused slots are {style}" + lower_bound),

        engine="vectors/1",
        rule="cortex-m.vector_table.shape",
        unknowns=[
            "entry count alone does not identify the exact part number "
            "(vendors differ on zeroed vs aliased unused vectors)",
            "handler targets are static addresses; runtime remapping (bootloader "
            "jump, IVT relocation, VTOR writes) is not modelled",
            f"only {MIN_ALIGN}-byte aligned offsets are considered (ARMv7-M requires the "
            f"table base to be power-of-two aligned, minimum {MIN_ALIGN} bytes)",
        ] + ([f"this image has no container header: the dump fixes the table's file "
              f"offset (0x{off:X}), not its address — the reported vaddr assumes the "
              f"inferred load base 0x{image.segments[0].vaddr:08X}"]
             if image.fmt == "raw" else []),
        metrics={"n_live": len(entries), "n_scanned": n_scanned, "zeroed_slots": zeros,
                 "unique_handlers": unique, "monotone_ratio": round(ratio, 3),
                 "slot_density": round(density, 3), "msp": f"0x{sp:08X}",
                 "reset": f"0x{reset:08X}", "table_vaddr": f"0x{vaddr:08X}",
                 "most_common_target": f"0x{default_handler:08X}", "unused_style": style,
                 "scan_stopped_early": stopped_early, "max_gap": MAX_GAP},

    )
    anchor, whence = seg.evidence_offset(off)
    f.add(Evidence(kind="bytes", note="initial MSP + reset vector (little endian)" + whence,
                   file_offset=anchor, vaddr=vaddr, hex=data[off:off + 8].hex()))
    anchor8, _ = seg.evidence_offset(off + 8)
    f.add(Evidence(kind="bytes", note="following handler entries" + whence,
                   file_offset=anchor8,
                   vaddr=vaddr + 8, hex=data[off + 8:off + 8 + 4 * min(6, len(entries))].hex()))
    return f


def proposed_bases(data: bytes, limit: int = 6) -> list[int]:
    """Origins the image's own putative vector tables imply.

    A dump of an application linked above a bootloader (OpenMV H7 puts its app at
    0x0802_0000 behind a 128 KB DFU bootloader) says nothing about where it lives, and
    enumerating linkers' favourite offsets would be a guess about other people's build
    systems.  The table itself answers the question: its second word is the reset
    handler, the reset handler is the first code after the vectors, and the vectors are
    at the start of the image — so `reset & ~0xFFFF` is the origin the image claims for
    itself.  This only *proposes*; `scan_tables` still has to accept the shape under
    that base before it can win, and the block histogram of a real dump produces a
    dozen candidates that all fail.
    """
    cand: Counter = Counter()
    trim = len(data) - len(data) % 4
    for off in range(0, trim - 8, MIN_ALIGN):
        sp, reset = struct.unpack_from("<II", data, off)
        if not reset & 1 or not any(lo <= (reset & ~1) <= hi for lo, hi in FLASH_LIKE):
            continue
        if not _in_ranges(sp, RAMISH):
            continue
        cand[(reset & ~1) & ~(FLASH_CAND_SPAN - 1)] += 1
    return [b for b, _n in sorted(cand.items(), key=lambda kv: (-kv[1], kv[0]))][:limit]


def infer_load_base(data: bytes, path: str = "<raw>",
                    bases: tuple[int, ...] | None = None,
                    min_entries: int = MIN_ENTRIES) -> tuple[int, int, int, dict[int, int]]:
    """Pick the load base of a headerless dump by *counting valid tables*.

    Bytes alone cannot say what address they live at, so the question is which
    assumed origin makes the image self-consistent.  For every canonical flash base
    — plus the origins the image's own reset vectors claim — the whole shape test
    runs.  The winner is the base whose *best* table is the most table-like: counting
    tables alone (the first version here) rewards a low origin, because reading a dump
    at the wrong base still lets its constant pools pass the handler test, and four
    half-plausible tables then beat the one real table the correct origin reveals.
    Table count is the tie-break, which is what still separates a merged
    bootloader+application dump (two tables only fit the low origin) from a standalone
    application dump.

    Returns (base, tables_at_best, first_table_file_offset, per_base_counts).
    """
    from .container import COMMON_FLASH_BASES, Image, Segment

    if bases is None:
        bases = tuple(dict.fromkeys(list(COMMON_FLASH_BASES) + proposed_bases(data)))
    else:
        bases = tuple(bases)
    best_base, best_key, first_off = 0, (-1.0, -1, 0.0, -1), 0
    counts: dict[int, int] = {}
    for base in bases:
        seg = Segment(base, data, "text", None, "raw", 0)
        image = Image(path, len(data), "raw", "arm", "little", None, [seg])
        tables = scan_tables(image, min_entries=min_entries)
        counts[base] = len(tables)
        if not tables:
            continue
        best = max(tables, key=lambda t: t.confidence)
        # (best-table confidence, #tables, how far the reset handler sits above its own
        # table, base): the reset distance is what says "this origin is where the code
        # actually starts", and the higher origin still wins an exact tie.
        head = int(best.metrics["reset"], 16) - int(best.metrics["table_vaddr"], 16)
        key = (best.confidence, len(tables), -float(head), base)
        if key > best_key:
            best_base, best_key = base, key
            first_off = int(tables[0].metrics["table_vaddr"], 16) - base
    return best_base, counts.get(best_base, 0), first_off, counts


def rank_socs(image: Image, socs: dict[str, Soc], table: Finding | None,
              explained: dict[str, dict]) -> list[Finding]:
    """Rank candidate SoCs by memory-map agreement, not by name guessing.

    `explained[name]` is `{"blocks": set, "addrs": set}` from the carve engine.
    Three numbers decide it, all of them per *distinct address constant*:

      coverage  - how much of the image's device evidence this map can see at all;
      lead      - how much of what it sees no other installed map can see;
      blind     - how much of what another map sees this one cannot.

    Counting block *names* (the first version) made the ranking a popularity
    contest for whichever map has the most aliases: an STM32F7 image scored
    "stm32f427xx, 87 blocks" because F4's GPIO/DMA windows sit exactly where F7's
    do, and the F4 map simply has more names to stick them under.  `blind` is
    what a wrong map cannot hide: it is the other map's evidence, missing here.

    The lead is also a warning: if a map explains *nothing* exclusively, the
    installed databases cannot separate these parts, and the report says so
    instead of naming the first candidate.
    """
    if not socs:
        return []
    msp = None
    if table:
        msp_s = table.metrics.get("msp", "")
        msp = int(msp_s, 16) if msp_s.startswith("0x") else None
    lo = min((s.vaddr for s in image.segments), default=0)
    hi = max((s.end for s in image.segments), default=0)

    names = sorted(set(explained) & set(socs))
    addrs = {n: set(explained[n]["addrs"]) for n in names}
    max_mine = max((len(a) for a in addrs.values()), default=0) or 1
    hits = {n: (socs[n].near_flash(lo), socs[n].near_ram(msp)) for n in names}
    rows = []
    for name in names:
        mine = addrs[name]
        others = set().union(*[addrs[o] for o in names if o != name]) if len(names) > 1 else set()
        lead, blind = len(mine - others), len(others - mine)
        flash_hit, ram_hit = hits[name]
        # the stack pointer is evidence too, and on F4-vs-F7 it is the only kind that
        # works: those two families share their peripheral windows almost exactly, so a
        # tie on constants is not a dead end when one map alone declares the RAM the
        # image resets into (CCM at 0x1000_0000 exists on F4, not on F7).  A contender
        # is a map that explains *everything* this one explains - `>=` on sets, not on
        # counts - so a third map that fits less of the image cannot veto a separation
        # it never had the evidence to make.
        contenders = [o for o in names if o != name and addrs[o] >= mine]
        ram_lead = bool(ram_hit) and not any(hits[o][1] for o in contenders)
        coverage = len(mine) / max_mine
        lead_rate = lead / len(mine) if mine else 0.0
        blind_rate = blind / (blind + len(mine)) if (blind + len(mine)) else 0.0
        score = (0.50 * coverage + 0.30 * lead_rate - 0.55 * blind_rate
                 + 0.06 * bool(flash_hit) + 0.09 * bool(ram_hit))
        if not mine and not flash_hit and not ram_hit:
            # Nothing in this image lands in that map: no device constant, and neither the
            # load region nor the reset stack pointer is inside a declared window.  A
            # `soc.candidate` row would put a part name on zero evidence -- which is how a
            # one-byte file used to come back as "stm32f427xx, conf 0.35".
            continue
        rows.append({"name": name, "score": score, "mine": len(mine), "lead": lead,
                     "blind": blind, "blocks": len(explained[name]["blocks"]),
                     "flash_hit": flash_hit, "ram_hit": ram_hit, "ram_lead": ram_lead,
                     "ambiguous": lead == 0 and not ram_lead})

    rows.sort(key=lambda r: (-r["score"], -r["mine"], r["name"]))
    top = rows[0]["score"] if rows else 0.0
    findings = []
    for rank, r in enumerate(rows[:4]):
        soc = socs[r["name"]]
        # a candidate is only as strong as its margin: second place within a few
        # hundredths of a point means the maps are not separable by this image
        contested = rank == 0 and len(rows) > 1 and rows[1]["score"] > top - 0.06
        conf = 0.35 + 0.62 * max(r["score"], 0.0)
        if r["ambiguous"] or contested or len(names) == 1:
            conf = min(conf, 0.58)
        elif r["lead"] == 0:
            # separated by the RAM map alone: real, but one pointer against a family
            # that shares every peripheral window this image touches
            conf = min(conf, 0.66)
        if rank > 0:
            conf = min(conf, 0.6)
        head = ("no installed map is distinctive here: " if r["ambiguous"] else
                "closest installed map, tied with an alternative: " if contested and rank == 0
                else "best match on the RAM map, not on device constants: "
                if r["lead"] == 0 and rank == 0
                else "best match: " if rank == 0 else f"runner-up (rank {rank + 1}): ")
        rival = next((o["name"] for o in rows if o["name"] != r["name"]), None)
        load = (f"inside flash base {r['flash_hit']}" if r["flash_hit"]
                else "outside every declared flash base")
        stack = (f"MSP inside RAM at {r['ram_hit']}" if r["ram_hit"]
                 else "MSP outside every declared RAM region")
        f = Finding(
            kind="soc.candidate",
            subject=r["name"],
            confidence=round(min(conf, 0.93), 3),
            summary=(f"{head}{r['name']}: {r['mine']} distinct device constants in this "
                     f"image land in its peripheral map ({r['blocks']} blocks), {r['lead']} "
                     f"of them in no other installed map, and {r['blind']} that another map "
                     f"explains are missing from it; load region {load}; "
                     f"{stack}"
                     + ("; the stack pointer is the only thing here that separates it from "
                        "the map it ties with on constants"
                        if r["lead"] == 0 and r["ram_lead"] else "")),
            engine="vectors/1",
            rule="soc.candidate.map-agreement",
            evidence=[Evidence(kind="region", note=f"image spans 0x{lo:08X}-0x{hi:08X}",
                               vaddr=lo, text=f"{hi - lo} bytes")],
            unknowns=[
                "several STM32 variants share a peripheral map; confirm with DBGMCU/IDCODE, "
                "option bytes or the vector-table entry count",
                f"database provenance: {soc.provenance.get('source_repo')}@"
                f"{str(soc.provenance.get('header_sha256'))[:12]}…",
            ] + (["no candidate has exclusive constants: the image cannot be pinned to one "
                  "part with the installed databases"] if r["ambiguous"] else [])
            + (["the peripheral constants in this image are identical under another "
                "installed map, so this ranking rests on the RAM declaration alone and "
                "one vector-table entry count would overturn it"]
               if r["lead"] == 0 and r["ram_lead"] else [])
            + (["only one database is installed, so nothing here was compared against an "
                "alternative map; add one with `python tools/gen_socdb.py build`"]
               if len(names) == 1 else [])
            + ([f"a second map scores within 0.06 of this one: the constants in this image "
                f"do not separate {r['name']} from {rival}"] if contested else [])
            + ([f"{len(rows) - 4} installed map(s) scored against this image but are not "
                f"reported: only the top 4 become findings, and their numbers are in "
                f"`socdb list`"] if rank == 0 and len(rows) > 4 else []),
            metrics={"constants_explained": r["mine"], "exclusive_constants": r["lead"],
                     "blind_constants": r["blind"], "blocks_explained": r["blocks"],
                     "score": round(r["score"], 4), "contested": contested,
                     "databases_installed": len(names),
                     "flash_base_ok": bool(r["flash_hit"]), "ram_base_ok": bool(r["ram_hit"]),
                     "ram_exclusive": bool(r["ram_lead"]),
                     "peripheral_count": len(soc.peripherals)},
        )
        findings.append(f)
    return findings
