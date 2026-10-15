"""Access to the generated SoC memory-map databases.

Databases under `data/` are produced by `tools/gen_socdb.py` straight from
vendor CMSIS headers, and each one carries the sha256 of the header it came
from.  If a base address in a firmprint report is wrong, the mistake is
traceable to a single upstream file — that is the point.
"""
from __future__ import annotations

import json
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).with_name("data")


#: Region sizes are not in the CMSIS `*_BASE` defines, so these are documented
#: upper bounds used only to ask "could this address be in that region" — never a
#: claim about the part's flash or SRAM size.  Every region in the shipped
#: databases starts at or above its own base and is smaller than both spans, so a
#: match means "plausible", not "proven".
FLASH_SPAN = 0x20_0000        # 2 MB
RAM_SPAN = 0x10_0000          # 1 MB

#: A Cortex-M7 maps its ITCM at the very bottom of the address map, and ST's own CMSIS
#: headers say so: `stm32f765xx.h` defines `RAMITCM_BASE 0x00000000UL` ("Base address
#: of : 16KB RAM reserved for CPU execution/instruction accessible over ITCM") and
#: `stm32h743xx.h` defines `D1_ITCMRAM_BASE (0x00000000UL)` ("64KB RAM reserved for CPU
#: execution/instruction accessible over ITCM").  Neither define reaches `ram_bases()`,
#: because `tools/gen_socdb.py` drops the base defines that are not peripherals — so an
#: image whose initial MSP is 0x0000_4000 (OpenMV3's) read as "outside every declared RAM
#: region" until this window was added.  Bounded at 64 KB, the largest ITCM either header
#: claims, and opened only for a core with TCM on a part that also declares RAM at
#: 0x2000_0000: on a Cortex-M4 the same low window is the *flash* alias, and counting it
#: as RAM there would be a category error, not a shortcut.
ITCM_ALIAS = (0x0000_0000, 0x0001_0000)
ITCM_CORES = ("cortex-m7", "cortex-m55", "cortex-m85")


@dataclass(slots=True)
class Soc:
    name: str
    family: str
    device: str
    core: str
    regions: dict[str, int]
    peripherals: dict[str, dict]
    types: dict[str, dict[str, list]]
    provenance: dict = field(default_factory=dict)
    _starts: list[int] = field(default_factory=list, repr=False)
    _ranges: list[tuple[int, int, str]] = field(default_factory=list, repr=False)
    _alias_starts: list[int] = field(default_factory=list, repr=False)
    _alias_ranges: list[tuple[int, int, str]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        named: list[tuple[int, int, str]] = []
        alias: list[tuple[int, int, str]] = []
        for pname, entry in self.peripherals.items():
            span = max(entry.get("size") or 4, 4)
            row = (entry["base"], entry["base"] + span, pname)
            (named if entry.get("type") else alias).append(row)
        named.sort()
        alias.sort()
        self._ranges = named
        self._starts = [r[0] for r in named]
        self._alias_ranges = alias
        self._alias_starts = [r[0] for r in alias]

    # -------------------------------------------------------------- address lookup
    def _at(self, addr: int, starts: list[int], rows: list[tuple[int, int, str]]
            ) -> tuple[str, int] | None:
        """Largest block base <= addr, then the smallest span there that reaches it.

        Nested blocks always start at or above their parent, so the last base at or
        below `addr` is the most specific answer.  When a sibling with that base
        stops short of `addr`, a wider enclosing block may still reach it; those are
        few, so the backward scan is bounded instead of turning every miss into an
        O(n) walk.
        """
        i = bisect_right(starts, addr) - 1
        if i < 0:
            return None
        start = rows[i][0]
        best = None
        j = i
        while j >= 0 and rows[j][0] == start:
            row = rows[j]
            if row[1] > addr and (best is None or row[1] < best[1]):
                best = row
            j -= 1
        if best is not None:
            return best[2], addr - start
        for k in range(i - 1, max(i - 17, -1), -1):
            s2, e2, n2 = rows[k]
            if s2 <= addr < e2:
                return n2, addr - s2
        return None

    def peripheral_at(self, addr: int) -> tuple[str, int] | None:
        """(peripheral, offset_from_base) if addr falls inside a known block.

        CMSIS defines two kinds of symbol at one address: GPIOA's own base and the
        bus anchor `AHB1PERIPH_BASE` that the header happens to place at the same
        value.  The anchor has no register struct, so if it were allowed to win a
        smallest-span contest a GPIOA reference would be reported as an anonymous
        bus region.  Structured blocks are therefore searched first and the alias
        list is only the fallback that says "this word is a region base".
        """
        hit = self._at(addr, self._starts, self._ranges)
        if hit:
            return hit
        return self._at(addr, self._alias_starts, self._alias_ranges)

    def is_peripheral(self, name: str) -> bool:
        """True when CMSIS gives the block a register struct.

        RAM, flash-array and bit-band windows share the address space with real
        peripherals but have no `*__TypeDef`; counting them as "peripheral
        access" would be a category error, so callers split them out.
        """
        return bool(self.peripherals.get(name, {}).get("type"))

    def register_name(self, periph: str, offset: int) -> str | None:
        """Resolve an instance offset to its CMSIS register name (None if the
        offset is a reserved hole or the peripheral has no struct type)."""
        tname = self.peripherals.get(periph, {}).get("type")
        if not tname:
            return None
        for rname, (off, size, _acc) in self.types.get(tname, {}).items():
            if off <= offset < off + max(size, 4):
                if offset != off and size > 4:
                    idx = (offset - off) // 4
                    return f"{rname}[{idx}]"
                if offset != off:
                    return None
                return rname
        return None

    def access_of(self, periph: str, offset: int) -> str | None:
        tname = self.peripherals.get(periph, {}).get("type")
        if not tname:
            return None
        for _rname, (off, size, acc) in self.types.get(tname, {}).items():
            if off <= offset < off + max(size, 4):
                return acc
        return None

    # ------------------------------------------------------------- region helpers
    def flash_bases(self) -> list[int]:
        """Declared flash origins: the `*_BASE` defines CMSIS names, plus ST's habit
        of putting the same region in the peripheral table under a FLASH-ish name."""
        keys = [k for k in self.regions if "FLASH" in k.upper()]
        keys += [k for k in self.peripherals if "FLASH" in k.upper()
                 and not self.peripherals[k].get("type")]
        return sorted({self._addr(k) for k in keys})

    def ram_bases(self) -> list[int]:
        keys = [k for k in self.regions if "RAM" in k.upper() or "SRAM" in k.upper()]
        keys += [k for k in self.peripherals if ("RAM" in k.upper() or "SRAM" in k.upper())
                 and not self.peripherals[k].get("type")]
        return sorted({self._addr(k) for k in keys})

    def _addr(self, key: str) -> int:
        if key in self.regions:
            return self.regions[key]
        return self.peripherals[key]["base"]

    def itcm_base(self) -> int | None:
        """The address this part's ITCM is reachable from at the bottom of the map.

        Only an M7-and-later core that also declares RAM at 0x2000_0000 gets the window;
        on a Cortex-M4 the same low addresses are the flash alias, so accepting them as
        RAM there would be a category error, not a shortcut.
        """
        if self.core in ITCM_CORES and 0x2000_0000 in self.ram_bases():
            return ITCM_ALIAS[0]
        return None

    def near_ram(self, addr: int | None) -> str | None:
        """Which declared RAM region an address sits in (within RAM_SPAN)."""
        if addr is None:
            return None
        for base in self.ram_bases():
            if base <= addr < base + RAM_SPAN:
                return f"0x{base:08X}"
        itcm = self.itcm_base()
        if itcm is not None and ITCM_ALIAS[0] <= addr < ITCM_ALIAS[1]:
            return f"0x{itcm:08X} (ITCM)"
        return None

    def near_flash(self, addr: int | None) -> str | None:
        if addr is None:
            return None
        for base in self.flash_bases():
            if base <= addr < base + FLASH_SPAN:
                return f"0x{base:08X}"
        return None

    def summary(self) -> dict:
        return {"device": self.device, "family": self.family, "core": self.core,
                "peripherals": len(self.peripherals), "struct_types": len(self.types),
                "provenance": {k: self.provenance.get(k) for k in
                               ("source_repo", "source_path", "header_sha256", "fetched_at")}}


def load_soc(path: str | Path, data_dir: Path | None = None) -> Soc:
    p = Path(path)
    if not p.exists():                       # bare database name ("stm32f427xx") is allowed
        candidate = (data_dir or DATA_DIR) / f"{p.name}.json"
        if candidate.exists():
            p = candidate
    raw = json.loads(p.read_text(encoding="utf8"))
    if raw.get("schema") != "firmprint-socdb/1":
        raise ValueError(f"{path}: unsupported socdb schema {raw.get('schema')!r}")
    return Soc(name=raw["device"], family=raw["family"], device=raw["device"], core=raw["core"],
               regions=raw["memory_regions"], peripherals=raw["peripherals"],
               types=raw["types"], provenance=raw["provenance"])


def available(data_dir: Path | None = None) -> list[str]:
    d = data_dir or DATA_DIR
    return sorted(p.stem for p in d.glob("*.json") if not p.name.startswith("_"))


def load_all(data_dir: Path | None = None) -> dict[str, Soc]:
    d = data_dir or DATA_DIR
    out = {}
    for name in available(d):
        try:
            out[name] = load_soc(d / f"{name}.json")
        except (ValueError, KeyError, json.JSONDecodeError) as exc:   # a bad DB must not kill a scan
            print(f"warning: skipping {name}: {exc}")
    return out
