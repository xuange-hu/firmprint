"""Score firmprint's findings against an oracle built from the image itself.

Why this exists: "the tool says GPIOE is used" is not checkable by a reader, so
a reviewer's only options are to trust us or to redo the work.  An ST/Arm
firmware built with the Hardware Abstraction Layer links one `HAL_<MODULE>_*`
function family per peripheral it actually drives, and the ELF symbol table
names those families.  That gives an independent answer key we never wrote:
compare the peripheral set firmprint derived from *addresses* against the
peripheral set the *linker* says has driver code in the image.

Honest limits, stated in the report too:
  * linked does not mean executed — a driver can be compiled in and never called;
  * firmprint is allowed to find things the oracle cannot see, because OpenMV's
    own C writes registers directly (DCMI, DMA streams, timing tweaks).  Those
    are reported as `unconfirmed`, not `false positive`;
  * the mapping below is a name bridge, not proof.  Every row keeps the symbol
    evidence so a reader can spot-check it.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from .analyze import analyze

#: HAL/LL module token -> CMSIS peripheral block-name prefixes (stm32f4/stm32h7)
MODULE_TO_BLOCKS: dict[str, tuple[str, ...]] = {
    "ADC": ("ADC1", "ADC2", "ADC3", "ADC12"),
    "CAN": ("CAN1", "CAN2"),
    "CORTEX": ("NVIC", "SCB", "SysTick"),
    "CRC": ("CRC",),
    "CRYP": ("CRYP",),
    "DAC": ("DAC",),
    "DCMI": ("DCMI",),
    "DMA": ("DMA1", "DMA2"),
    "DMA2D": ("DMA2D",),
    "DSI": ("DSI",),
    "DFSDM": ("DFSDM",),
    "EXTI": ("EXTI",),
    "FMC": ("FMC", "FSMC"),
    "GPIO": ("GPIOA", "GPIOB", "GPIOC", "GPIOD", "GPIOE", "GPIOF", "GPIOG",
             "GPIOH", "GPIOI", "GPIOJ", "GPIOK"),
    "HASH": ("HASH",),
    "I2C": ("I2C1", "I2C2", "I2C3", "I2C4"),
    "IWDG": ("IWDG",),
    "LTDC": ("LTDC",),
    "OCTOSPI": ("OCTOSPI1", "OCTOSPI2"),
    "QUADSPI": ("QUADSPI",),
    "RNG": ("RNG",),
    "RTC": ("RTC",),
    "SDMMC": ("SDMMC1", "SDMMC2", "SDIO"),
    "SPI": ("SPI1", "SPI2", "SPI3", "SPI4", "SPI5", "SPI6"),
    "SAI": ("SAI1", "SAI2"),
    "TIM": ("TIM1", "TIM2", "TIM3", "TIM4", "TIM5", "TIM6", "TIM7", "TIM8",
            "TIM9", "TIM10", "TIM11", "TIM12", "TIM13", "TIM14", "TIM15",
            "TIM16", "TIM17"),
    "USART": ("USART1", "USART2", "USART3", "USART6"),
    "UART": ("USART1", "USART2", "USART3", "UART4", "UART5", "USART6"),
    "UART7": ("UART7", "UART8"),
    "SDIO": ("SDIO",),
    "SPDIFRX": ("SPDIFRX",),
    "CEC": ("CEC",),
    "USB": ("OTG_FS", "OTG_HS", "USB_OTG"),
    "WWDG": ("WWDG",),
    "PWR": ("PWR",),
    "RCC": ("RCC",),
    "FLASH": ("FLASH_R",),
}

_HAL_RE = re.compile(r"\bHAL_([A-Z0-9]+?)_")
_LL_RE = re.compile(r"\b(?:ll|LL)_([a-zA-Z0-9]+?)_")


def symbol_oracle(symbols: dict[int, str]) -> tuple[dict[str, int], dict[str, list[str]]]:
    """(module -> linked symbol count, module -> sample symbol names)."""
    modules: Counter[str] = Counter()
    samples: dict[str, list[str]] = {}
    for name in symbols.values():
        m = _HAL_RE.search(name) or _LL_RE.search(name)
        if not m:
            continue
        tok = m.group(1).upper()
        if tok in MODULE_TO_BLOCKS or len(tok) <= 8:
            modules[tok] += 1
            samples.setdefault(tok, []).append(name)
    return dict(modules), {k: sorted(v)[:3] for k, v in samples.items()}


def detected_peripherals(report: dict) -> dict[str, set]:
    """Peripheral blocks a report claims, with the engine(s) that produced them."""
    detected: dict[str, set] = {}
    for f in report["findings"]:
        if f["kind"] == "peripheral.materialised":
            for n in f["metrics"].get("peripherals", []):
                detected.setdefault(n, set()).add(f["engine"])
        elif f["kind"] in ("peripheral.access", "peripheral.usage"):
            detected.setdefault(f["subject"], set()).add(f["engine"])
    return detected


def compare(report: dict, modules: dict[str, int]) -> dict:
    """Join firmprint's peripheral findings with the driver-name oracle."""
    detected = detected_peripherals(report)

    rows = []
    for module, count in sorted(modules.items(), key=lambda kv: -kv[1]):
        blocks = MODULE_TO_BLOCKS.get(module)
        if not blocks:
            continue
        hit = [b for b in blocks if b in detected]
        rows.append({
            "oracle_module": module,
            "linked_symbols": count,
            "expected_blocks": list(blocks),
            "firmprint_blocks": hit,
            "status": "confirmed" if hit else "missed",
            "engines": sorted({e for b in hit for e in detected[b]}),
        })

    known = {b for r in rows for b in r["expected_blocks"]}
    extra = sorted(n for n in detected if n not in known)
    per_engine = Counter()
    for _name, engines in detected.items():
        per_engine["+".join(sorted(engines))] += 1

    covered = [r for r in rows if r["status"] == "confirmed"]
    return {
        "rows": rows,
        "detected_peripherals": len(detected),
        "oracle_modules": len(rows),
        "confirmed": len(covered),
        "missed": [r["oracle_module"] for r in rows if r["status"] == "missed"],
        "recall_over_drivers": round(len(covered) / max(len(rows), 1), 3),
        "unconfirmed_peripherals": extra,
        "peripherals_by_engine": dict(per_engine),
    }


def cmd_verify(a) -> int:
    report = analyze(a.file, soc_name=a.soc, data_dir=Path(a.data_dir) if a.data_dir else None,
                     budget=a.budget, full=a.full)
    image_mods, samples = symbol_oracle(_symbols_of(a.file))
    result = compare(report, image_mods)
    print(_render(report, result, samples, a.file))
    if a.json:
        Path(a.json).write_text(json.dumps({"meta": report["meta"], "verify": result},
                                           indent=2, default=str) + "\n", encoding="utf8")
        print(f"wrote {a.json}")
    return 0


def _symbols_of(path: str) -> dict[int, str]:
    from .container import load
    return load(path).symbols


def _render(report: dict, r: dict, samples: dict[str, list[str]], path: str) -> str:
    meta = report["meta"]
    decoded = meta["decode"].get("instructions") or 0
    out = [f"# verification: {Path(path).name}", "",
           f"- image sha256 `{meta['file']['sha256']}`",
           f"- matched part **{meta['soc']['device']}**; {r['detected_peripherals']} peripheral "
           f"block(s) with address evidence; {decoded:,} instructions decoded",
           f"- oracle: {r['oracle_modules']} driver module(s) named by the image's own symbols",
           ]
    if not r["oracle_modules"]:
        out.append("**no oracle available**: this image carries no function symbols, so there "
                   "is nothing independent to score against. The findings below are unverified "
                   "claims with evidence; run the same scan on a symbol-carrying build to score it.")
        out += ["", f"peripheral blocks reported: {r['detected_peripherals']}",
                "", f"contract: {len(report['contract']['violations'])} violation(s)"]
        return "\n".join(out) + "\n"
    out += [f"- **confirmed {r['confirmed']}/{r['oracle_modules']}** "
            f"(recall {r['recall_over_drivers']:.0%}) over driver-linked peripherals",
            "",
           "| oracle module | linked symbols | firmprint block(s) | status | engine(s) |",
           "|---|---|---|---|---|"]
    for row in r["rows"]:
        blocks = ", ".join(row["firmprint_blocks"]) or "-"
        eng = ", ".join(row["engines"]) or "-"
        mark = "OK" if row["status"] == "confirmed" else "MISSED"
        out.append(f"| {row['oracle_module']} | {row['linked_symbols']} | {blocks} | {mark} | {eng} |")
    out += ["",
            f"Peripheral blocks firmprint reported that the driver oracle has no name for "
            f"({len(r['unconfirmed_peripherals'])}): "
            + (", ".join(r["unconfirmed_peripherals"]) or "none"),
            "",
            "Those are not counted as false positives: the oracle only knows about peripherals "
            "with a HAL/LL driver family in the symbol table, and direct register writes from "
            "application code are invisible to it. Each one still carries offsets and bytes.",
            ""]
    if r["missed"]:
        out.append("Missed drivers, with the symbol evidence that should have anchored them:")
        for m in r["missed"][:12]:
            out.append(f"- {m}: " + ", ".join(samples.get(m, [])[:3]))
        out.append("")
    out.append(f"contract: {len(report['contract']['violations'])} violation(s)")
    return "\n".join(out) + "\n"


def verify_markdown(path: str, soc: str | None = None, budget: int | None = None,
                    full: bool = False) -> str:
    """Library entry point used by tools/make_verification.py and the test suite."""
    report = analyze(path, soc_name=soc, budget=budget, full=full)
    modules, samples = symbol_oracle(_symbols_of(path))
    return _render(report, compare(report, modules), samples, path)
