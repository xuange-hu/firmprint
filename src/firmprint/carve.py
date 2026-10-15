"""Stdlib-only analysis: constant carving, entropy and strings.

Carving answers "which peripherals does this blob even mention" without a
disassembler.  It looks for 32-bit words that land inside a known peripheral
block, which is where compilers park register addresses (literal pools, struct
initialisers, DMA descriptors).  It is deliberately conservative and never
claims a *read* or *write* — that is the capstone engine's job.
"""
from __future__ import annotations

import math
import re
import struct
from collections import Counter, defaultdict

from .container import Image
from .evidence import Evidence, Finding
from .socdb import Soc

_STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")


def _prefix_index(soc: Soc) -> set[int]:
    """16-bit prefixes a peripheral-block address can start with (fast reject)."""
    out = set()
    for entry in soc.peripherals.values():
        base, size = entry["base"], max(entry.get("size") or 4, 4)
        out.add(base >> 16)
        out.add((base + size) >> 16)
    return out


def classify_word(word: int, soc: Soc, prefixes: set[int],
                  exclude: list[tuple[int, int]]) -> tuple[str, tuple[str, str | None] | None]:
    """One word against one memory map: (verdict, (block, register)).

    Single implementation for both engines so they cannot drift: `carve_bases`
    counts the verdicts, `explained_constants` only wants the hits.  Verdicts:

      prefix    - not even close to a block base; the fast reject
      pointer   - a code/data address inside this image, not a device address
      unexplained - a peripheral-ish word in a hole of this map (used later for
                  "which map covers this image best")
      unnamed_offset - inside a device block, but at an offset CMSIS does not
                  name.  Compilers do not emit those; IEEE-754 constants do,
                  because the floats 2.000-2.063 are byte-identical to STM32's
                  APB1 window (0x4000_0000-0x4001_FFFF).
      hit       - a plausible device-register constant
    """
    if (word >> 16) not in prefixes:
        return "prefix", None
    if any(lo <= word < hi for lo, hi in exclude):
        return "pointer", None
    found = soc.peripheral_at(word)
    if not found:
        return "unexplained", None
    periph, delta = found
    reg = soc.register_name(periph, delta)
    if delta and reg is None and soc.is_peripheral(periph):
        return "unnamed_offset", None
    return "hit", (periph, reg)


def carve_bases(image: Image, soc: Soc, exclude_ranges=None,
                ev_cap: int = 6) -> tuple[dict, dict, dict]:
    """Return (counts, evidence, stats) for address constants inside known blocks.

    counts and evidence are keyed by (peripheral, register_name_or_None).  The
    count is exact; evidence is capped at `ev_cap` so a report stays readable —
    conflating the two is how a tool ends up claiming "8 references" everywhere.

    exclude_ranges drops values that are really pointers into the image itself
    (a literal pool full of code addresses would otherwise look like a device
    that touches everything).
    """
    prefixes = _prefix_index(soc)
    exclude = list(exclude_ranges or [])
    counts: dict[tuple, int] = defaultdict(int)
    hits: dict[tuple, list[Evidence]] = defaultdict(list)
    stats = {"words_examined": 0, "candidate_words": 0, "excluded_pointers": 0,
             "unnamed_offsets": 0, "unexplained_words": 0}
    verdicts = {"pointer": "excluded_pointers", "unnamed_offset": "unnamed_offsets",
                "unexplained": "unexplained_words"}
    for seg in image.segments:
        data = seg.data
        trim = len(data) - (len(data) % 4)
        for idx, (word,) in enumerate(struct.iter_unpack("<I", data[:trim])):
            off = idx * 4
            stats["words_examined"] += 1
            verdict, hit = classify_word(word, soc, prefixes, exclude)
            if verdict != "hit":
                bucket = verdicts.get(verdict)
                if bucket:
                    stats[bucket] += 1
                continue
            stats["candidate_words"] += 1
            periph, reg = hit
            key = (periph, reg)
            counts[key] += 1
            if len(hits[key]) < ev_cap:
                foff, whence = seg.evidence_offset(off)
                hits[key].append(Evidence(
                    kind="word", note=f"0x{word:08X} = {periph}"
                                      + (f"+{reg}" if reg else " (block base)") + whence,
                    file_offset=foff,
                    vaddr=seg.vaddr + off, hex=data[off:off + 4].hex()))
    return counts, hits, stats


def explained_constants(image: Image, soc: Soc, exclude_ranges=None) -> dict:
    """What one memory map can see in this image: {blocks, addrs}.

    Counted per *distinct address*, not per block name: two parts can both have a
    block called PWR at different addresses, and name counting then rewards the
    map with more aliases instead of the map that fits the bytes.
    """
    prefixes = _prefix_index(soc)
    exclude = list(exclude_ranges or [])
    blocks: set[str] = set()
    addrs: set[int] = set()
    for seg in image.segments:
        data = seg.data
        for (word,) in struct.iter_unpack("<I", data[:len(data) - (len(data) % 4)]):
            verdict, hit = classify_word(word, soc, prefixes, exclude)
            if verdict != "hit":
                continue
            periph, _reg = hit
            if soc.is_peripheral(periph):
                blocks.add(periph)
                addrs.add(word)
    return {"blocks": blocks, "addrs": addrs}


def peripheral_usage(counts: dict, hits: dict) -> dict[str, dict]:
    """Fold (periph, register) evidence into a per-peripheral view."""
    per: dict[str, dict] = {}
    for (pname, reg), n in counts.items():
        entry = per.setdefault(pname, {"total": 0, "registers": {}, "evidence": []})
        entry["total"] += n
        entry["registers"][reg or "(block base)"] = n
        entry["evidence"].extend(hits.get((pname, reg), [])[:2])
    return per


def usage_findings(per: dict[str, dict], soc: Soc, engine: str = "carve/1") -> list[Finding]:
    out = []
    for pname, entry in sorted(per.items(), key=lambda kv: -kv[1]["total"]):
        regs = sorted(entry["registers"].items(), key=lambda kv: -kv[1])
        base = soc.peripherals[pname]["base"]
        is_per = soc.is_peripheral(pname)
        kind = "peripheral.usage" if is_per else "memory.reference"
        why = ("registers seen: " if is_per else "no CMSIS register struct: this is a "
               "memory or bit-band window, so it is reported as a memory reference; ")
        f = Finding(
            kind=kind,
            subject=pname,
            confidence=0.55 if entry["total"] < 3 else 0.7 if entry["total"] < 10 else 0.82,
            summary=(f"{pname} @0x{base:08X} referenced {entry['total']} times "
                     f"as an address constant; " + why
                     + ", ".join(f"{r}({n})" for r, n in regs[:6])),
            engine=engine,
            rule=("peripheral.usage.carved-constants" if is_per
                  else "memory.reference.carved-constants"),
            evidence=list(entry["evidence"]),
            unknowns=[
                "carving proves the constant exists in the image, not that code "
                "executes an access to it",
                "no read/write direction: use the capstone engine for that",
            ],
            metrics={"references": entry["total"],
                     "registers": dict(regs)},
        )
        out.append(f)
    return out


def entropy_regions(image: Image, block: int = 0x1000) -> list[dict]:
    """Per-block Shannon entropy: flat-high blocks are compressed or encrypted."""
    rows = []
    for seg in image.segments:
        for off in range(0, len(seg.data), block):
            chunk = seg.data[off:off + block]
            if len(chunk) < 256:
                continue
            counts = Counter(chunk)
            n = len(chunk)
            # `-0.0` is what `-sum(0.0)` prints as; a report showing a negative
            # entropy for an erased block looks like a bug, so clamp the sign.
            ent = max(0.0, -sum((c / n) * math.log2(c / n) for c in counts.values() if c))
            rows.append({"vaddr": seg.vaddr + off, "size": len(chunk), "entropy": round(ent, 3),
                         "segment": seg.name or seg.source,
                         "class": ("encrypted/compressed candidate" if ent > 7.9 else
                                   "packed data" if ent > 7.4 else "code/text")})
    rows.sort(key=lambda r: r["vaddr"])
    return rows


def entropy_finding(image: Image, block: int = 0x1000) -> Finding | None:
    rows = entropy_regions(image, block)
    if not rows:
        return None
    hi = [r for r in rows if r["entropy"] > 7.9]
    top = max(rows, key=lambda r: r["entropy"])
    f = Finding(
        kind="region.entropy",
        subject=f"{len(hi)} high-entropy block(s)",
        confidence=0.6 if hi else 0.4,
        summary=(f"max entropy {top['entropy']:.2f} bits/byte at 0x{top['vaddr']:08X}; "
                 f"{len(hi)}/{len(rows)} blocks above 7.9 (encrypted or compressed payload)"),
        engine="carve/1",
        rule="region.entropy.shannon",
        evidence=[Evidence(kind="region", note=f"block starting at 0x{r['vaddr']:08X}",
                           vaddr=r["vaddr"], count=r["size"],
                           text=f"entropy {r['entropy']} bits/byte") for r in hi[:6]],
        unknowns=["entropy cannot distinguish TLS/PSK-encrypted OTA from plain deflate; "
                  "correlation with a container magic is required for a firm claim"],
        metrics={"blocks": len(rows), "high_entropy_blocks": len(hi),
                 "max_entropy": top["entropy"], "max_entropy_vaddr": f"0x{top['vaddr']:08X}"},
    )
    return f


def strings_finding(image: Image, minlen: int = 8, limit: int = 400) -> Finding | None:
    """ASCII runs, filtered: `minlen` is a real filter, not decoration.

    The regex accepts 6-char runs because that is the shortest useful token, but
    a 6-char accident is not an identity hint, so `minlen` filters it out.

    Two things the first version got wrong, both on the real OpenMV sample:
    * stopping at `limit` kept strings meant the scan never reached the code area
      where the build banner lives — a firmware's useful strings are scattered, so
      hints are collected over the *whole* image and `limit` only caps the sample;
    * a loose hint pattern ('contains @ or /') promoted random ASCII runs out of
      packed image data to `strongest identity hints`, which is worse than silence:
      the reader trusts the line that sounds specific. A hint now has to read like
      writing *and* carry a token that actually identifies something.
    """
    found: list[tuple[int, str]] = []
    hints: list[tuple[int, str]] = []
    total = 0
    for seg in image.segments:
        for m in _STRING_RE.finditer(seg.data):
            s = m.group().decode("ascii")
            if len(s) < minlen or not _informative(s):
                continue
            total += 1
            if len(found) < limit:
                found.append((seg.vaddr + m.start(), s))
            if _reads_as_text(s) and _HINT_RE.search(s) and len(hints) < _HINT_CAP:
                hints.append((seg.vaddr + m.start(), s))
    if not found:
        return None
    head = f"{len(found)} of {total} human-readable string(s) kept"
    if hints:
        hints.sort(key=lambda a_s: (-_hint_rank(a_s[1]), a_s[0]))
        more = "at least " if len(hints) >= _HINT_CAP else ""
        tail = (f"; {more}{len(hints)} read as identity hints, strongest: "
                + "; ".join(f"'{h[:60]}'" for _a, h in hints[:5]))
    else:
        tail = ("; none of them reads like a build string, so there is no textual "
                "identity evidence in this image")
    f = Finding(
        kind="region.strings",
        subject=f"{len(found)} informative strings",
        confidence=0.62 if hints else 0.45,
        summary=head + tail,
        engine="carve/1",
        rule="region.strings.informative",
        evidence=[Evidence(kind="string", note="ASCII run", vaddr=a, text=s[:120])
                  for a, s in (hints[:6] or found[:6])],
        unknowns=[
            "strings surviving in a blob does not prove the corresponding code path runs",
            "the kept list is the first "
            f"{len(found)} of {total} informative string(s) by address; the hint search "
            "covered the whole image, the sample did not",
        ],
        metrics={"count": len(found), "informative_total": total, "hint_count": len(hints)},
    )
    return f


#: tokens that identify a build rather than decorate one. Deliberately narrow: a
#: generic "has an @ sign" rule turns packed JPEG bytes into a firmware version.
_HINT_RE = re.compile(
    r"(stm32[a-z0-9]*|s[tm]\d{3}[a-z]\d?|cortex[ -_]?m\d|micropython|openmv|"
    r"\bversion\b|\bbuild\b|\brev\.?\s*\d|\bv\d+\.\d+(\.\d+)?\b|\bgit\b|"
    r"https?://|[\w.-]+\.(?:c|h|cpp|py)\b|@[\w.-]+\.[a-z]{2,})", re.I)
#: collected per image. The strongest hint is usually late in a big blob, so this is a
#: memory bound, not a "first N by address" bound — the list is re-ranked before display.
_HINT_CAP = 400

_PART_RE = re.compile(r"(?:\bstm\d{2}[tfh]\d{3,4}(?:[a-z]\d?)?\b)"   # STM32F427, STM32H743
                      r"|(?:\b[tfh]\d{3,4}(?:[a-z]\d?)?\b)"          # bare F427 in a banner
                      r"|(?:\bat9[16]\w*\d+\b|\bsam\d+\b)"
                      r"|(?:cortex[ -_]?m\d)", re.I)
_BRAND_RE = re.compile(r"(openmv|micropython|stm32|st\s*micro)", re.I)


def _hint_rank(s: str) -> int:
    """A part number identifies, a product name narrows, a path only dates the build.

    `unavailable on your OpenMV Cam.` is a brand mention, not an identity claim; the
    banner `OPENMV2 with STM32F427` carries a device code and must sort above it.
    """
    if _PART_RE.search(s):
        return 3
    if _BRAND_RE.search(s):
        return 2
    if re.search(r"[\w.-]+\.(?:c|h|cpp|py)\b|https?://", s, re.I):
        return 1
    return 0


def _reads_as_text(s: str) -> bool:
    """Contains a four-letter word, and is not mostly punctuation.

    The word-shaped run is the real discriminator: random printable bytes from
    packed data (`@1Q`Qh`h`, `C,I)@%j*C`) never contain one, while a part number
    like `stm32f429_init.c` is legitimately digit-heavy and would fail a strict
    letter-ratio test.
    """
    letters = sum(c.isalpha() for c in s)
    return letters >= 0.5 * len(s) and bool(re.search(r"[A-Za-z]{4}", s))


def _informative(s: str) -> bool:
    """Reject pathological ASCII (all same char, long digit runs, register dumps)."""
    if len(set(s)) < 3:
        return False
    if re.fullmatch(r"[\W_]+", s):
        return False
    return sum(c.isdigit() for c in s) / len(s) <= 0.7
