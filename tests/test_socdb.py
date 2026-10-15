"""The databases must agree with the vendor headers, or nothing else matters."""
from __future__ import annotations

from pathlib import Path

import pytest

from firmprint.socdb import available, load_all, load_soc

# Values below are transcribed from ST's reference manuals, not from this tool:
# RM0390 (STM32F427) and RM0399 (STM32H743).  If a generator change breaks the
# CMSIS parser, one of these rows fails before any analysis can be believed.
F4_EXPECTED = {
    "GPIOA": 0x4002_0000,      # AHB1
    "RCC": 0x4002_3800,
    "FLASH_R": 0x4002_3C00,
    "PWR": 0x4000_7000,        # APB1
    "CAN1": 0x4000_6400,
    "USART1": 0x4001_1000,     # APB2
    "ADC1": 0x4001_2000,
    "SDIO": 0x4001_2C00,
    "SYSCFG": 0x4001_3800,
    "EXTI": 0x4001_3C00,
    "TIM2": 0x4000_0000,
    "DMA1": 0x4002_6000,
    "DBGMCU": 0xE004_2000,
}
# Offsets below are the RM0390 RCC register map, not a transcription of this tool.
F4_RCC_REGISTERS = {"CR": 0x00, "PLLCFGR": 0x04, "CFGR": 0x08, "CIR": 0x0C,
                    "AHB1RSTR": 0x10, "AHB2RSTR": 0x14, "AHB3RSTR": 0x18,
                    "APB1RSTR": 0x20, "APB2RSTR": 0x24, "AHB1ENR": 0x30,
                    "APB2ENR": 0x44, "APB1ENR": 0x40, "BDCR": 0x70, "CSR": 0x74}
F4_RCC_HOLES = (0x1C, 0x28, 0x2C, 0x48, 0x68)
H7_EXPECTED = {
    "GPIOA": 0x5802_0000,      # AHB3 - moved versus F4, which is why this is a test
    "RCC": 0x5802_4400,
    "USART1": 0x4001_1000,
    "ADC1": 0x4002_2000,
    "SDMMC1": 0x5200_7000,
    "PWR": 0x5802_4800,
    "SYSCFG": 0x5800_0400,
    "EXTI": 0x5800_0000,
    "TIM2": 0x4000_0000,
}


def test_databases_are_installed():
    names = available()
    assert "stm32f427xx" in names and "stm32h743xx" in names


#: RM0433 (STM32F765) section 1.3 memory map.  The second and third rows are the
#: ones that matter for the case study: an F7 image sits in an F4's peripheral
#: windows almost everywhere, so the part can only be separated by the blocks the
#: F4 map does not contain at all.
F7_EXPECTED = {
    "GPIOA": 0x4002_0000,      # AHB1 - identical to F4, on purpose
    "RCC": 0x4002_3800,
    "PWR": 0x4000_7000,        # APB1
    "USART1": 0x4001_1000,     # APB2
    "TIM2": 0x4000_0000,
    "DMA1": 0x4002_6000,
    "DBGMCU": 0xE004_2000,
    "DMA2D": 0x4002_B000,      # Chrom-ART: no F427 equivalent
    "SAI1": 0x4001_5800,
    "SDMMC1": 0x4001_2C00,
    "FMC_Bank1_R": 0xA000_0000,
    "QSPI_R": 0xA000_1000,
}
#: DFSDM1 is checked separately below: CMSIS puts the filter channels at the same
#: address as the block, so `peripheral_at` correctly answers with the more specific
#: `DFSDM1_Channel0` instead of the window name.
F7_ALIASES = {"DFSDM1": 0x4001_7400, "QSPI": 0x9000_0000}


@pytest.mark.parametrize("device,expected", [("stm32f427xx", F4_EXPECTED),
                                             ("stm32f765xx", F7_EXPECTED),
                                             ("stm32h743xx", H7_EXPECTED)])
def test_peripheral_bases_match_the_reference_manual(device, expected):
    soc = load_soc(device)
    for name, base in expected.items():
        assert name in soc.peripherals, f"{device}: {name} missing from the database"
        assert soc.peripherals[name]["base"] == base, f"{device}: {name} wrong base"
        # and the bisect lookup used by every finding must round-trip
        assert soc.peripheral_at(base) is not None
        assert soc.peripheral_at(base)[0] == name


def test_f7_memory_map_names_the_blocks_the_reference_manual_draws():
    """The DFSDM window and the QSPI byte address space exist on an F7 and not on an F4.

    These are the aliases that carry no register struct, so they are reported as a
    region rather than a peripheral access - and they are also what the OpenMV3 image
    can be pinned with while an F4 image cannot.
    """
    soc = load_soc("stm32f765xx")
    for name, base in F7_ALIASES.items():
        assert soc.peripherals[name]["base"] == base
        assert not soc.is_peripheral(name), f"{name} is an alias, not a structured block"
    f4 = load_soc("stm32f427xx")
    assert "QSPI" not in f4.peripherals and "DFSDM1" not in f4.peripherals


def test_rcc_register_offsets_come_from_the_struct():
    """Every name the report can print for RCC must be at the manual's offset."""
    soc = load_soc("stm32f427xx")
    for reg, off in F4_RCC_REGISTERS.items():
        assert soc.register_name("RCC", off) == reg, f"{reg} not at 0x{off:02X}"
    # Reserved holes resolve to None rather than to a neighbouring register: a
    # confident wrong name is worse than no name.
    for off in F4_RCC_HOLES:
        assert soc.register_name("RCC", off) is None, f"0x{off:02X} is reserved"


def test_array_registers_index_then_stop_at_their_span():
    soc = load_soc("stm32f427xx")
    # GPIOA->AFR[2] is at 0x20..0x27; 0x24 is the second element, 0x28 is outside.
    assert soc.register_name("GPIOA", 0x20) == "AFR"
    assert soc.register_name("GPIOA", 0x24) == "AFR[1]"
    assert soc.register_name("GPIOA", 0x28) is None
    assert soc.register_name("GPIOA", 0x40) is None      # past the whole struct


def test_memory_windows_are_not_peripherals():
    """A RAM base has no register struct, so it must never be called an access."""
    soc = load_soc("stm32f427xx")
    assert not soc.is_peripheral("SRAM1")
    assert not soc.is_peripheral("CCMDATARAM")
    assert soc.is_peripheral("RCC")
    assert soc.is_peripheral("FLASH_R")          # the controller, not the array


def test_nested_blocks_resolve_to_the_more_specific_one():
    soc = load_soc("stm32f427xx")
    base = soc.peripherals["DMA1"]["base"]
    stream = soc.peripherals.get("DMA1_Stream3")
    if stream:
        assert soc.peripheral_at(stream["base"])[0] == "DMA1_Stream3"
    assert soc.peripheral_at(base + 0x10)[0].startswith("DMA1")


def test_provenance_is_recorded():
    soc = load_soc("stm32f427xx")
    p = soc.provenance
    assert p["source_repo"].startswith("STMicroelectronics/")
    assert len(p["header_sha256"]) == 64
    assert p["source_path"].endswith(".h")


def test_load_all_skips_a_corrupt_database_instead_of_dying(tmp_path, capsys):
    import json
    import shutil

    from firmprint.socdb import DATA_DIR

    for n in available():
        shutil.copy(DATA_DIR / f"{n}.json", tmp_path / f"{n}.json")
    (tmp_path / "broken.json").write_text(json.dumps({"schema": "nope"}))
    socs = load_all(tmp_path)
    assert "stm32f427xx" in socs
    assert "broken" not in socs
    assert "skipping broken" in capsys.readouterr().out


def test_peripheral_at_returns_none_outside_every_block():
    soc = load_soc("stm32f427xx")
    assert soc.peripheral_at(0x9999_9999) is None
    assert soc.peripheral_at(0) is None


def test_the_cortex_m7_itcm_window_counts_as_ram_and_the_m4_one_does_not():
    """An initial SP of 0x0000_4000 is RAM on an F7 and flash on an F4.

    The OpenMV3 vector table resets into 0x0000_4000, and `ram_bases()` never contains
    it: `tools/gen_socdb.py` drops the base defines that are not peripherals, and
    `stm32f765xx.h` names that window `RAMITCM_BASE 0x00000000UL` — "16KB RAM reserved
    for CPU execution/instruction accessible over ITCM".  Reading it as "MSP outside
    every RAM region" threw away the one address that separates an F7 from an F4.  On a
    Cortex-M4 the same low window is the *flash* alias, so the window is opened only for
    cores that have an ITCM at all.
    """
    f7, f4 = load_soc("stm32f765xx"), load_soc("stm32f427xx")
    assert f7.itcm_base() == 0x0000_0000
    assert f7.near_ram(0x0000_4000) == "0x00000000 (ITCM)"
    assert f4.itcm_base() is None
    assert f4.near_ram(0x0000_4000) is None
    # a declared region answers for its own addresses; the window is only the low 64 KB
    assert f7.near_ram(0x2002_1000) == "0x20000000"      # RAM_SPAN covers DTCM+SRAM1
    assert f7.near_ram(0x0001_0000) is None              # stops at the largest ITCM claimed


# ------------------------------------------------ the generator must be reproducible

def _load_generator():
    """`tools/gen_socdb.py` is a checkout-only script (a wheel ships built maps)."""
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[1] / "tools" / "gen_socdb.py"
    if not script.exists():
        pytest.skip("the generator lives in the repository checkout")
    spec = importlib.util.spec_from_file_location("gen_socdb", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, script.parent.parent


def _cached_header(device: str) -> Path:
    """Raw CMSIS headers are cached under socdb-src/ and deliberately not committed."""
    header = Path(__file__).resolve().parents[1] / "socdb-src" / f"{device}.h"
    if not header.exists():
        pytest.skip(f"run: python tools/gen_socdb.py fetch --device {device}")
    return header


def test_a_shipped_map_is_exactly_reproducible_from_the_bundled_header(tmp_path):
    """Anyone can regenerate `src/firmprint/data/*.json` from the CMSIS header in
    `socdb-src/`.  If this ever drifts, the shipped maps are unverifiable folklore."""
    import hashlib
    import json

    gen, _root = _load_generator()
    header = _cached_header("stm32f427xx")
    built = gen.build("f4", "stm32f427xx", header, repo="local", path=str(header))
    out = tmp_path / "stm32f427xx.json"
    out.write_text(json.dumps(built, indent=1) + "\n", encoding="utf8")

    mine = json.loads(out.read_text(encoding="utf8"))
    assert mine["peripherals"] == shipped_map("stm32f427xx")["peripherals"]
    assert mine["types"] == shipped_map("stm32f427xx")["types"]
    assert mine["memory_regions"] == shipped_map("stm32f427xx")["memory_regions"]
    # the header bytes behind the map are hashed, and the hash is checkable
    assert built["provenance"]["header_sha256"] == hashlib.sha256(header.read_bytes()).hexdigest()
    assert built["provenance"]["header_bytes"] == header.stat().st_size


def test_a_regenerated_map_answers_the_same_address_questions(tmp_path):
    import json

    gen, _root = _load_generator()
    header = _cached_header("stm32h743xx")
    built = gen.build("h7", "stm32h743xx", header, repo="local", path=str(header))
    out = tmp_path / "stm32h743xx.json"
    out.write_text(json.dumps(built, indent=1) + "\n", encoding="utf8")

    soc = load_soc("stm32h743xx", data_dir=tmp_path)      # bare name resolved inside data_dir
    ref = load_soc("stm32h743xx")                         # the shipped map
    assert soc.name == "stm32h743xx"
    assert soc.peripherals["GPIOA"]["base"] == 0x5802_0000 == ref.peripherals["GPIOA"]["base"]
    assert soc.peripheral_at(0x5802_0400) == ref.peripheral_at(0x5802_0400)
    assert soc.register_name("RCC", 0x210) == ref.register_name("RCC", 0x210)


def shipped_map(device: str) -> dict:
    import json
    from pathlib import Path

    return json.loads((Path(__file__).resolve().parents[1] / "src" / "firmprint" /
                       "data" / f"{device}.json").read_text(encoding="utf8"))
