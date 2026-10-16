"""The oracle: an answer key the tool did not write, and what it can therefore prove.

`verify` is the part of this project a reviewer should be most suspicious of, because
it is the part that grades the tool.  These tests hold it to the rule the README
claims: the score comes from the image's own symbols, the join is only made over
modules that name a real peripheral block, and a claim the oracle cannot see is
reported as unconfirmed rather than wrong.
"""
from __future__ import annotations

import pytest
from conftest import cortex_m_image

from firmprint import container, verify
from firmprint.verify import compare, symbol_oracle

# ------------------------------------------------------------------ the oracle itself


def test_the_oracle_counts_a_driver_family_not_a_lucky_symbol(elf_path):
    """One HAL function is a coincidence; a linked family is a fact about the build."""
    image = container.load(str(elf_path))
    modules, samples = symbol_oracle(image.symbols)
    assert modules["GPIO"] >= 2
    assert all(n.startswith("HAL_") or n.lower().startswith("ll_")
               for names in samples.values() for n in names)
    # samples are evidence for a human to spot-check, not a dump of the symbol table
    assert all(len(v) <= 3 for v in samples.values())


def test_the_oracle_ignores_symbols_that_name_no_module(elf_path):
    image = container.load(str(elf_path))
    modules, _ = symbol_oracle(image.symbols)
    assert not [t for t in modules if len(t) > 8], "a whole function name leaked into a module token"


def test_a_dump_without_symbols_gives_no_oracle(tmp_path):
    p = tmp_path / "bare.bin"
    p.write_bytes(cortex_m_image(code_bytes=0x400))
    assert symbol_oracle(container.load(str(p)).symbols) == ({}, {})


# ------------------------------------------------------------------------ the join


def test_only_modules_that_name_a_block_are_scored(elf_path):
    """`HAL_SD_*` is a real driver family with no single CMSIS block, so it is not a miss."""
    image = container.load(str(elf_path))
    modules, _ = symbol_oracle(image.symbols)
    result = compare({"findings": []}, modules)
    rows = result["rows"]
    scored = {r["oracle_module"] for r in rows}
    assert scored <= set(modules)
    for r in rows:
        assert r["expected_blocks"], f"{r['oracle_module']} was scored without a block to look for"
    # an unmapped token must not silently become a `missed` entry
    assert "SD" in modules and "SD" not in scored
    assert "SD" not in result["missed"]


def test_every_row_that_is_confirmed_keeps_the_block_that_confirmed_it(elf_path):
    image = container.load(str(elf_path))
    modules, _ = symbol_oracle(image.symbols)
    report = verify.run_verification(str(elf_path))[0]
    result = compare(report, modules)
    assert result["confirmed"] == result["oracle_modules"], \
        "the shipped sample used to score lower; a regression here means findings lost blocks"
    for row in result["rows"]:
        assert row["status"] == "confirmed"
        assert row["firmprint_blocks"]
        assert row["engines"], f"{row['oracle_module']} confirmed by no engine"
        assert all(b in row["expected_blocks"] for b in row["firmprint_blocks"])
    assert result["recall_over_drivers"] == 1.0
    assert result["missed"] == []


def test_a_peripheral_the_oracle_cannot_name_is_unconfirmed_not_wrong(elf_path):
    """OpenMV writes DCMI timing and DMA stream registers with its own C.

    The oracle only knows driver families, so those findings have no answer key.
    Calling them false positives would grade the tool on the oracle's blindness.
    """
    report = {"findings": [{"kind": "peripheral.usage", "subject": "FMC",
                            "engine": "carve/1", "metrics": {}},
                           {"kind": "peripheral.materialised", "subject": "x",
                            "engine": "capstone/1",
                            "metrics": {"peripherals": ["OTG_FS"]}}]}
    result = compare(report, {"GPIO": 3})
    gpio = next(r for r in result["rows"] if r["oracle_module"] == "GPIO")
    assert gpio["status"] == "missed"
    # neither FMC nor OTG_FS is in any GPIO row, so both land in the unconfirmed list
    assert sorted(result["unconfirmed_peripherals"]) == ["FMC", "OTG_FS"]
    assert result["confirmed"] == 0 and result["oracle_modules"] == 1


def test_detected_peripherals_merges_the_engines_that_saw_the_same_block():
    report = {"findings": [
        {"kind": "peripheral.access", "subject": "USART1", "engine": "capstone/1", "metrics": {}},
        {"kind": "peripheral.usage", "subject": "USART1", "engine": "carve/1", "metrics": {}},
        {"kind": "peripheral.materialised", "subject": "ignored", "engine": "carve/1",
         "metrics": {"peripherals": ["USART1", "TIM2"]}}]}
    detected = verify.detected_peripherals(report)
    assert detected["USART1"] == {"capstone/1", "carve/1"}
    assert detected["TIM2"] == {"carve/1"}
    # `peripheral.materialised` subjects are counts, not block names: only the metric
    # list may introduce a block, or every materialised finding would also claim itself
    assert "ignored" not in detected


# ------------------------------------------------------------- one file read per run


def test_verification_scores_the_image_it_scanned(monkeypatch, elf_path):
    """The answer key and the findings must come from the same bytes.

    `verify` used to open the file three times (hash, segments, symbols), so a
    rebuild between reads scored one image against another image's symbols.  The
    single load is now observable: `analyze` is handed that image, and nothing
    else opens the file.
    """
    loads = []
    real_load = container.load
    seen: dict = {}

    def counted(path, *a, **kw):
        loads.append(str(path))
        return real_load(path, *a, **kw)

    def spy_analyze(path, **kw):
        seen["image"] = kw.get("image")
        return {"meta": {"file": {"path": str(path), "size": 1, "sha256": "0" * 64},
                         "container": {}, "soc": None, "decode": {},
                         "carve_stats": {}},
                "findings": [], "contract": {"strict": True, "violations": []}}

    monkeypatch.setattr(container, "load", counted)
    monkeypatch.setattr(verify, "analyze", spy_analyze)
    report, result, samples = verify.run_verification(str(elf_path))
    assert len(loads) == 1, f"the file was opened {len(loads)} times"
    assert seen["image"] is not None, "analyze re-opened the file instead of reusing the image"
    assert seen["image"].raw == elf_path.read_bytes(), \
        "the bytes the report hashes are not the bytes the segments came from"
    assert result["rows"] or not samples


@pytest.mark.parametrize("flag,expected", [(False, 0), (True, 1)])
def test_strict_decides_the_exit_code_of_a_verification(monkeypatch, capsys, flag, expected):
    """`verify` is the audit command, and it used to be unable to fail.

    The violation list is printed either way; `--strict` is what lets a pipeline gate
    on it -- the same rule `scan --strict` documents in `evidence.validate`.
    """
    report = {"meta": {"file": {"path": "x.elf", "size": 1, "sha256": "0" * 64},
                       "container": {"symbol_count": 3}, "soc": {"device": "stm32f427xx"},
                       "decode": {"instructions": 12}, "carve_stats": {}},
              "findings": [], "contract": {"strict": True,
                                           "violations": ["peripheral.usage/GPIOE: no evidence"]}}
    result = {"rows": [{"oracle_module": "GPIO", "linked_symbols": 4,
                        "expected_blocks": ["GPIOE"], "firmprint_blocks": [],
                        "status": "missed", "engines": []}],
              "detected_peripherals": 0, "oracle_modules": 1, "confirmed": 0,
              "missed": ["GPIO"], "recall_over_drivers": 0.0,
              "unconfirmed_peripherals": [], "peripherals_by_engine": {}}
    monkeypatch.setattr(verify, "run_verification", lambda *a, **kw: (report, result, {}))
    argv = ["verify", "x.elf"] + (["--strict"] if flag else [])
    assert verify.cmd_verify(_ns(argv)) == expected
    text = capsys.readouterr().out
    assert "contract: 1 violation(s)" in text
    assert "MISSED" in text


def _ns(argv):
    """A parsed namespace, so this exercises cmd_verify rather than argparse."""
    import argparse
    return argparse.Namespace(file="x.elf", soc=None, base=None, data_dir=None,
                              budget=None, full=False, json=None,
                              strict="--strict" in argv)


def test_verify_renders_the_missed_drivers_with_their_symbols(capsys, monkeypatch):
    """A miss without the symbol that caused it is a number nobody can re-check."""
    report = {"meta": {"file": {"path": "x.elf", "size": 1, "sha256": "0" * 64},
                       "container": {}, "soc": None, "decode": {}, "carve_stats": {}},
              "findings": [], "contract": {"strict": True, "violations": []}}
    result = {"rows": [{"oracle_module": "LTDC", "linked_symbols": 9,
                        "expected_blocks": ["LTDC"], "firmprint_blocks": [],
                        "status": "missed", "engines": []}],
              "detected_peripherals": 0, "oracle_modules": 1, "confirmed": 0,
              "missed": ["LTDC"], "recall_over_drivers": 0.0,
              "unconfirmed_peripherals": [], "peripherals_by_engine": {}}
    out = verify._render(report, result, {"LTDC": ["HAL_LTDC_Init", "HAL_LTDC_ConfigLayer"]}, "x.elf")
    assert "LTDC" in out and "HAL_LTDC_Init" in out
    assert "recall 0%" in out
