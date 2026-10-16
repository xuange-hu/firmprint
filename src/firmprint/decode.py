"""Optional capstone engine: real instruction decoding with register tracking.

Installed, capstone turns "the constant 0x40011000 exists somewhere" into
"`ll_uart_init` at 0x0802AB10 stores R2 to USART1+0x0000 (CR1)".  Absent, the
scan still works on carving alone and the report says so instead of pretending.

Register values are tracked by a flow-insensitive sweep that resets at function
boundaries (push/pop/bl/bx) — a deliberate trade: fewer false "this register
still holds that base" claims at the cost of missing values that survive a
branch.  Every finding records the limitation rather than hiding it.
"""
from __future__ import annotations

import re
import struct
from collections import Counter, defaultdict

from .container import Image, Segment
from .evidence import Evidence, Finding
from .socdb import Soc

CAPSTONE = None
try:                                     # optional dependency, checked once
    import capstone as CAPSTONE  # type: ignore
except Exception:                        # noqa: BLE001 - missing/broken lib is expected
    CAPSTONE = None

DEFAULT_CODE_BUDGET = 0x8_0000           # 512 KB of decoded code by default


def engine_label() -> str:
    """`capstone/<version>` -- the version of the library that actually decoded the bytes.

    An engine label is provenance, so it has to be the number a reviewer can re-create:
    capstone's own `__version__` lags its distribution (the 5.0.9 wheel still prints
    "5.0.7"), which would put a version on every finding that `pip show` denies installing.
    Distribution metadata first, module string when the package has none (a vendored or
    in-tree build), and never a guess.
    """
    if CAPSTONE is None:
        return ""
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return f"capstone/{version('capstone')}"
        except PackageNotFoundError:
            pass
    except Exception:                    # noqa: BLE001 - metadata is a nicety, not a dep
        pass
    return f"capstone/{CAPSTONE.__version__}"


#: the address range ARM reserves for memories and peripherals, below the
#: private peripheral bus (0xE000_0000+, whose NVIC/SysTick/SCB registers live in
#: the *core* header rather than the device header, so a device database cannot
#: be blamed for not naming them).
DEVICE_SPACE = (0x4000_0000, 0xDFFF_FFFF)

#: how many unmapped device addresses a report names; the count stays exact
_UNMAPPED_LIST_CAP = 24

#: how many instruction records one (peripheral, register, direction) key keeps as evidence.
#: A count is never taken from this list -- see `_TALLY`.
_EVIDENCE_CAP = 24

#: private key under which `_record` accumulates the true counts, removed from `stats`
#: before the report is built so no internal field reaches a reader or the JSON schema.
_TALLY = "_access_tally"

_IMM_RE = re.compile(r"#\s*(-?0x[0-9a-fA-F]+|-?\d+)")
_REG_RE = re.compile(r"\br(\d{1,2})\b")
# capstone prints base registers as bare names ("pc", "sp", "lr", "r0"..,"r12"),
# so the alternatives must be full tokens — an "r" prefix on the whole group made
# every literal-pool load (`ldr r3, [pc, #0x18]`) invisible, which is how most
# firmware actually materialises a peripheral base.
_MEM_RE = re.compile(r"\[\s*(?P<base>pc|sp|lr|r\d{1,2})"
                     r"(?:\s*,\s*#(?P<off>-?0x[0-9a-fA-F]+|-?\d+))?\s*\]")


def available() -> bool:
    return CAPSTONE is not None


def _num(text: str) -> int | None:
    m = _IMM_RE.search(text)
    if not m:
        return None
    tok = m.group(1)
    try:
        return int(tok, 16) if tok.startswith(("0x", "-0x")) else int(tok)
    except ValueError:
        return None


def _reg(op: str) -> int | None:
    m = _REG_RE.search(op.split(",")[0]) if op else None
    if not m:
        return None
    v = m.group(1)
    return int(v) if v.isdigit() else {"r8": 8, "r9": 9, "r10": 10, "r11": 11, "r12": 12,
                                       "sp": 13, "lr": 14, "pc": 15}.get(v)


def _regnum(name: str) -> int | None:
    """'r0' / 'sp' / 'lr' / 'pc' -> register number, matching capstone's text form."""
    if not name:
        return None
    n = name.lower()
    special = {"pc": 15, "sp": 13, "lr": 14, "ip": 12, "sb": 9, "sl": 10,
               "fp": 11, "r9": 9}
    if n in special:
        return special[n]
    if n.startswith("r") and n[1:].isdigit():
        v = int(n[1:])
        return v if v <= 15 else None
    return None


def _mem(ops: str) -> tuple[str, int] | None:
    m = _MEM_RE.search(ops)
    if not m:
        return None
    base = m.group("base")
    reg = {"pc": 15, "sp": 13, "lr": 14}.get(base)
    if reg is None:
        reg = int(base[1:]) if base[1:].isdigit() else None
    if reg is None:
        return None
    off = m.group("off")
    val = 0
    if off:
        try:
            val = int(off, 16) if off.startswith(("-0x", "0x")) else int(off)
        except ValueError:
            return None
    return base, val


def decode_code(image: Image, soc: Soc, budget: int = DEFAULT_CODE_BUDGET,
                full: bool = False, others: dict[str, Soc] | None = None) -> tuple[list[Finding], dict]:
    """Return peripheral-access findings plus coverage stats.

    `others` is every *other* installed map: an address this map cannot name but
    another one can is counter-evidence against the match, and it is only worth
    reporting as such when the comparison was actually made.
    """
    if CAPSTONE is None:
        return [], {"engine": None}
    cs = CAPSTONE.Cs(CAPSTONE.CS_ARCH_ARM,
                     CAPSTONE.CS_MODE_THUMB | CAPSTONE.CS_MODE_LITTLE_ENDIAN)
    cs.detail = False

    code_segs = [s for s in image.segments if s.kind == "text"] or \
        [s for s in image.segments if s.name and "text" in (s.name or "")]
    stats = {"engine": engine_label(), "bytes_decoded": 0,
             "instructions": 0, "segments": len(code_segs), "coverage": 0.0,
             "functions": 0, "resyncs": 0, "memory_hits": 0}
    total = sum(len(s.data) for s in code_segs)
    limit = total if full else min(total, budget)

    accesses: dict[tuple, list[Evidence]] = defaultdict(list)
    immediates: dict[tuple, list[Evidence]] = defaultdict(list)
    unmapped: Counter[int] = Counter()
    sites: dict[int, Evidence] = {}

    # Decode function by function rather than as one flat stream: capstone stops at
    # the first undecodable halfword, and the head of .text on STM32 is the vector
    # table (data), not code.  Symbols give us real instruction boundaries and let
    # every finding name the function that produced it.
    windows = _function_windows(image, code_segs, limit, stats)
    # One byte may only be counted once.  Adjacent symbols produce windows that overlap
    # (`max(nxt - a, 2)` widens a two-byte function), and a window can end on bytes
    # capstone never consumed, so adding `len(chunk)` per window double-counted the
    # overlap and counted padding as decoded -- which is how `coverage` could print over
    # 100%.  A per-segment byte map settles it: coverage is the union of what was actually
    # turned into instructions.
    covers = {id(s): bytearray(len(s.data)) for s in code_segs}
    for seg, start, length in windows:
        _walk(cs, seg, start, length, soc, image, accesses, immediates, stats, unmapped,
              sites, covers[id(seg)])

    stats["bytes_decoded"] = sum(sum(c) for c in covers.values())
    stats["coverage"] = round(decoded_total(stats) / max(total, 1), 4)
    ranked = sorted(unmapped, key=lambda a: (-unmapped[a], a))
    stats["unmapped_device_accesses"] = sum(unmapped.values())
    stats["unmapped_device_constants"] = len(ranked)
    # count is exact, list is capped: the same rule the carve engine follows, so a
    # reader never mistakes "12 addresses" for "there were only 12"
    stats["unmapped_addresses"] = [f"0x{a:08X}" for a in ranked[:_UNMAPPED_LIST_CAP]]
    findings = _fold(accesses, immediates, soc, image, stats)
    stats.pop(_TALLY, None)          # internal accumulator, never part of a report
    gap = _coverage_finding(soc, ranked, unmapped, sites, others or {}, stats)
    if gap:
        findings.append(gap)
    return findings, stats


def _coverage_finding(soc: Soc, ranked: list[int], unmapped: Counter, sites: dict[int, Evidence],
                      others: dict[str, Soc], stats: dict) -> Finding | None:
    """Report what the chosen map could NOT name, with the address that proves it.

    Confidence here is deliberately modest and split: an instruction really did
    address the word (that part is as solid as the decode), but whether the miss means
    "wrong SoC" or "CMSIS does not model this block" depends on the other maps - so
    only the addresses another installed map *does* name are called a threat to the
    match, and a bare miss against a single map is reported as a coverage gap instead.
    """
    if not ranked:
        return None
    top = ranked[:_UNMAPPED_LIST_CAP]
    explained: dict[str, list[int]] = {}
    for name, other in others.items():
        if name == soc.name:
            continue
        hits = [a for a in top if (h := other.peripheral_at(a)) and other.is_peripheral(h[0])]
        if hits:
            explained[name] = hits
    claimed = sorted({a for hits in explained.values() for a in hits})
    ev = [sites[a] for a in top if a in sites][:8]
    if not ev:                                   # a claim with no place is decoration
        return None
    rival = max(explained, key=lambda n: len(explained[n])) if explained else None
    conf = 0.6 if claimed else 0.45
    summary = (f"{len(ranked)} device address(es) reached by decoded instructions are not "
               f"in {soc.name}'s map ({stats['unmapped_device_accesses']} accesses, e.g. "
               f"{', '.join(f'0x{a:08X}' for a in top[:6])})")
    if claimed:
        summary += (f"; {len(claimed)} of them ARE in {', '.join(sorted(explained))}"
                    f"{'' if rival is None else f' (most under {rival})'} - another installed "
                    f"map sees hardware this one does not")
    else:
        summary += ("; no other installed map names them either, so this is a hole in the "
                    "databases or a vendor block CMSIS does not define, not evidence of a "
                    "wrong part")
    return Finding(
        kind="soc.coverage",
        subject=soc.name,
        confidence=conf,
        summary=summary,
        engine=stats["engine"],
        rule="soc.coverage.unmapped-device-access",
        evidence=ev,
        unknowns=[
            "an address outside a map is not a claim about what the part is: unmodeled "
            "vendor blocks, external memory, and DMA-addressed peripherals all look the same",
            "a mis-paired MOVW/MOVT produces an address no part has ever had, so this list "
            "is a coverage gap, not a hardware inventory",
            # Only say "lower bound" when the comparison really was truncated; claiming
            # a limit that does not exist is as misleading as hiding one that does.
            (f"only the first {_UNMAPPED_LIST_CAP} of {len(ranked)} addresses are compared "
             f"against the other maps, so the count of contested addresses is a lower bound"
             if len(ranked) > _UNMAPPED_LIST_CAP else
             f"all {len(ranked)} address(es) were compared against the other maps, so the "
             "contested count is exact for this decode"),
            "0xE000_0000 and above is the ARM core (NVIC/SysTick/SCB) and lives in the "
            "core header, so it is excluded from this gap by construction",
        ],
        metrics={"addresses": len(ranked), "accesses": stats["unmapped_device_accesses"],
                 "contested": len(claimed),
                 "contested_by": {n: len(h) for n, h in explained.items()},
                 "other_maps_compared": len([n for n in others if n != soc.name])},
    )


def decoded_total(stats: dict) -> int:
    return stats["bytes_decoded"]


def _function_windows(image: Image, code_segs, limit: int, stats: dict):
    """(segment, offset, length) per function, bounded by the next symbol."""
    windows = []
    budget = limit
    for seg in code_segs:
        addrs = sorted(a for a in image.symbols if seg.vaddr <= a < seg.end)
        if not addrs:
            # A zero-length window decodes nothing, so do not record one: the budget
            # really did mean "no instruction decoding".
            length = min(len(seg.data), budget)
            if length:
                windows.append((seg, 0, length))
            stats["resyncs"] += 1
            continue
        for i, a in enumerate(addrs):
            nxt = addrs[i + 1] if i + 1 < len(addrs) else seg.end
            length = min(max(nxt - a, 2), 4096)
            length = min(length, budget)
            if length < 2:
                continue
            budget -= length
            stats["functions"] += 1
            windows.append((seg, a - seg.vaddr, length))
            if budget <= 0:
                return windows
    return windows


def _walk(cs, seg: Segment, start: int, length: int, soc: Soc, image: Image,
          accesses: dict, immediates: dict, stats: dict,
          unmapped: Counter | None = None, sites: dict[int, Evidence] | None = None,
          cover: bytearray | None = None) -> None:
    """Flow-insensitive immediate/register sweep across one function body."""
    state: dict[int, tuple[int, bool]] = {}       # reg -> (value, complete32)
    pc = (seg.vaddr + start) | 1
    chunk = seg.data[start:start + length]
    pos = 0
    while pos < len(chunk):
        produced = 0
        for insn in cs.disasm(chunk[pos:], pc + pos):
            produced += 1
            stats["instructions"] += 1
            if cover is not None:
                cover[start + pos:start + pos + insn.size] = b"\x01" * insn.size
            _step(insn, soc, image, state, accesses, immediates, stats, unmapped, sites)
            pos += insn.size
        if not produced:
            pos += 2                                # resync: skip the bad halfword
            stats["resyncs"] += 1
    if cover is None:
        # standalone callers (tests) that pass no byte map still get a walk distance,
        # measured in bytes actually consumed rather than in window length
        stats["bytes_decoded"] += pos


def _step(insn, soc: Soc, image: Image, state: dict, accesses: dict,
          immediates: dict, stats: dict, unmapped: Counter | None = None,
          sites: dict[int, Evidence] | None = None) -> None:
    raw = bytes(insn.bytes)
    addr = insn.address & ~1
    mn, ops = insn.mnemonic, insn.op_str
    if mn in ("push", "pop", "bx", "bl", "blx", "cbz", "cbnz", "b"):
        # `it`/`ite`/`itt` deliberately do NOT clear: an if-then block touches no
        # registers, and resetting here hid every `it ne` + `strne` register write.
        state.clear()
        if mn in ("bx", "bl", "blx", "b"):
            return
    if mn == "movw":
        r, v = _reg(ops), _num(ops)
        if r is not None and v is not None:
            state[r] = (v & 0xFFFF, False)
    elif mn == "movt":
        r, v = _reg(ops), _num(ops)
        if r is not None and v is not None:
            prev, _ = state.get(r, (0, False))
            cur = ((v & 0xFFFF) << 16) | (prev & 0xFFFF)
            state[r] = (cur, True)
            _record(immediates, soc, cur, addr, image, mn, ops, raw=raw, stats=stats)
    elif mn == "mov" and "#" in ops:
        r, v = _reg(ops), _num(ops)
        if r is not None and v is not None:
            state[r] = (v & 0xFFFF_FFFF, True)
            _record(immediates, soc, v, addr, image, mn, ops, raw=raw, stats=stats)
    elif mn == "add" and "#" in ops:
        dst = _reg(ops)
        rest = ops.split(",", 1)[1] if "," in ops else ""
        src = _reg(rest)
        k = _num(rest)
        if dst is not None and src is not None and k is not None and src in state:
            val = (state[src][0] + k) & 0xFFFF_FFFF
            state[dst] = (val, state[src][1])
            _record(immediates, soc, val, addr, image, mn, ops, raw=raw, stats=stats)
    elif mn.startswith("ldr") and "[" in ops:
        base = _mem(ops)
        if not base:
            return
        bname, off = base
        dst = _reg(ops)
        if bname == "pc":
            # PC-relative literal: the ARM ARM counts the offset from
            # (instruction address + 4) aligned down to 4, not from the
            # instruction address itself.
            lit = ((addr + 4) & ~3) + off
            word = image.read(lit, 4)
            if word:
                val = struct.unpack("<I", word)[0]
                if dst is not None:
                    state[dst] = (val, True)
                _record(immediates, soc, val, addr, image, mn, f"{ops} -> 0x{val:08X}", raw=raw, stats=stats)
        else:
            regnum = _regnum(bname)
            if regnum in state and state[regnum][1]:
                direction = "read" if mn.startswith("ldr") else None
                if direction:
                    _record(accesses, soc, (state[regnum][0] + off) & 0xFFFF_FFFF,
                            addr, image, mn, ops, direction, raw=raw, stats=stats,
                            unmapped=unmapped, sites=sites)
    elif mn.startswith("str"):
        base = _mem(ops)
        if not base:
            return
        bname, off = base
        regnum = _regnum(bname)
        if regnum in state and state[regnum][1]:
            _record(accesses, soc, (state[regnum][0] + off) & 0xFFFF_FFFF,
                    addr, image, mn, ops, "write", raw=raw, stats=stats,
                    unmapped=unmapped, sites=sites)


def _record(bucket: dict, soc: Soc, value: int, addr: int, image: Image,
             mn: str, ops: str, direction: str | None = None,
             raw: bytes = b"", stats: dict | None = None,
             unmapped: Counter | None = None,
             sites: dict[int, Evidence] | None = None) -> None:
    found = soc.peripheral_at(value)
    if not found:
        # An instruction really did address this and the chosen map has no block for
        # it: counter-evidence against the map, not silence.  The caller checks the
        # address against every installed database before the report decides whether
        # coverage is a problem.
        if (unmapped is not None and direction and
                DEVICE_SPACE[0] <= value <= DEVICE_SPACE[1]):
            unmapped[value] += 1
            if sites is not None and value not in sites:
                sites[value] = _instruction_evidence(soc, value, addr, image, mn, ops,
                                                     direction, raw)
        return
    periph, delta = found
    if not soc.is_peripheral(periph):
        # RAM / flash-array / bit-band window: a real access, but not a
        # peripheral claim.  The carve engine reports these as memory.reference.
        if stats is not None:
            stats["memory_hits"] = stats.get("memory_hits", 0) + 1
        return
    reg = soc.register_name(periph, delta)
    key = (periph, reg, direction)
    # The evidence list is capped, the count is not.  Without this tally a row that saw 40
    # stores to one register printed "24 decoded load/store(s)" -- an exact-looking number
    # that was really `min(N, 24)`, the failure mode the carve engine goes out of its way to
    # avoid (carve.py keeps count and evidence separate for exactly this reason).
    if stats is not None:
        stats.setdefault(_TALLY, Counter())[(periph, reg, direction)] += 1
    if len(bucket[key]) >= _EVIDENCE_CAP:
        return
    bucket[key].append(_instruction_evidence(soc, value, addr, image, mn, ops, direction, raw))


def _instruction_evidence(soc: Soc, value: int, addr: int, image: Image, mn: str, ops: str,
                          direction: str | None, raw: bytes) -> Evidence:
    """One reproducible load/store site, named by the map whether it matches or not.

    The address the instruction reached is part of the note even when the map has no
    block for it - "0x40013C00 is not in this database" is only checkable if the
    reader can see which address was meant.
    """
    fn = _nearest_symbol(image, addr)
    seg = image.find(addr)
    file_off, whence = (None, "")
    if seg is not None:
        rel = seg.offset_of(addr)
        if rel is not None:
            file_off, whence = seg.evidence_offset(rel)
    hit = soc.peripheral_at(value)
    label = ""
    if hit and soc.is_peripheral(hit[0]):
        reg = soc.register_name(hit[0], hit[1])
        label = f" -> {hit[0]}+0x{hit[1]:03X} ({reg or 'unmodeled offset'})"
    return Evidence(
        kind="instruction",
        note=(f"0x{addr:08X} {mn} {ops}" + (f"  [{direction}]" if direction else "")
              + (f"  in {fn}" if fn else "") + f"  reached 0x{value:08X}{label}" + whence),
        vaddr=addr, file_offset=file_off,
        hex=bytes(raw).hex(),
        text=f"{mn} {ops}")


def _nearest_symbol(image: Image, addr: int) -> str | None:
    if not image.symbols:
        return None
    best = None
    for saddr, name in image.symbols.items():
        if saddr <= addr and (best is None or saddr > best[0]):
            best = (saddr, name)
    return best[1] if best else None


def _fold(accesses: dict, immediates: dict, soc: Soc, image: Image, stats: dict) -> list[Finding]:
    out: list[Finding] = []
    per: dict[str, dict] = {}
    tally = stats.get(_TALLY) or {}
    for (periph, reg, direction), evs in accesses.items():
        # the tally is the truth; `evs` is at most `_EVIDENCE_CAP` records of it
        n = tally.get((periph, reg, direction), len(evs))
        entry = per.setdefault(periph, {"accesses": 0, "regs": defaultdict(int), "ev": [],
                                        "capped": False})
        entry["accesses"] += n
        entry["regs"][(reg or "(block base)", direction)] = \
            entry["regs"][(reg or "(block base)", direction)] + n
        entry["ev"].extend(evs[:3])
        if n > len(evs):
            entry["capped"] = True
    for pname, entry in sorted(per.items(), key=lambda kv: -kv[1]["accesses"]):
        top = sorted(entry["regs"].items(), key=lambda kv: -kv[1])[:8]
        f = Finding(
            kind="peripheral.access",
            subject=pname,
            confidence=0.86 if entry["accesses"] >= 5 else 0.74,
            summary=(f"{pname}: {entry['accesses']} decoded load/store(s) through a tracked base "
                     f"register; " + ", ".join(f"{r}/{d}={n}" for (r, d), n in top)),
            engine=stats["engine"],
            rule="peripheral.access.tracked-base-register",
            evidence=list(entry["ev"]),
            unknowns=[
                "base-register tracking resets at function boundaries, so a base held across a "
                "branch is counted as unknown rather than guessed",
                "offsets are static; index registers and peripheral aliases are not resolved",
            ] + ([f"the count is the full total; evidence records for one register and "
                  f"direction stop after {_EVIDENCE_CAP} sites"] if entry["capped"] else []),
            metrics={"accesses": entry["accesses"],
                     "registers": {f"{r}/{d}": n for (r, d), n in top}},
        )
        out.append(f)

    imm_total = sum(tally.get(k, len(v)) for k, v in immediates.items())
    imm_capped = any(tally.get(k, 0) > len(v) for k, v in immediates.items())
    if imm_total:
        names = sorted({k[0] for k in immediates})
        sample = [e for v in list(immediates.values())[:4] for e in v[:1]]
        f = Finding(
            kind="peripheral.materialised",
            subject=f"{len(names)} peripheral(s) built by immediate pairs",
            confidence=0.7,
            summary=(f"{imm_total} decoded MOVW/MOVT/LDR-literal sites materialise an address "
                     f"inside a known block ({', '.join(names[:8])})"),
            engine=stats["engine"],
            rule="peripheral.materialised.immediate",
            evidence=sample,
            unknowns=["MOVW/MOVT only gives the low 16 bits until the MOVT half is seen; "
                      "partial pairs are reported as block membership, not register access"]
                     + ([f"the site count is the full total; evidence records stop after "
                         f"{_EVIDENCE_CAP} sites per key"] if imm_capped else []),
            metrics={"sites": imm_total, "peripherals": names,
                     "decode_coverage": stats["coverage"], "instructions": stats["instructions"]},
        )
        out.append(f)
    return out
