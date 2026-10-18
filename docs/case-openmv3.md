# Case 2 — the sample that broke the ranking, and then proved it

OpenMV3 is the STM32F765 board, and it is the reason the part-ranking code was rewritten
twice.  The F4 sample tells you the tool can be honest about a tie; this one tells you the
tool can be *wrong* about a tie and notice.

```bash
python tools/get_sample.py --board OPENMV3   # 6 files, pinned by sha256
```

`firmware.bin`: 1,635,112 bytes, sha256 `f6c41e63f19591d0…`, no container metadata.

---

## 1. The load base, with three candidates

```
$ firmprint scan samples/openmv3/firmware.bin
file        firmware.bin  1,635,112 B  sha256:f6c41e63f19591d0…
container   raw / arm  1 segment(s)  entry -
            raw dump: no container header. load base inferred as 0x08020000: of the 17 origins
            tested it is the one whose best candidate reads most like a vector table (1 table(s)
            there, the first at file offset 0x0); origins that also produced tables: 0x08000000(1),
            0x08010000(2). Pass --base to pin it.
match       stm32f765xx (f7, cortex-m7)  conf 0.76  best match
```

`0x08020000` is the true application base: OpenMV3 puts a **128 KB** bootloader in front
of the firmware where OpenMV2 used 64 KB, and the proposal set (`reset & ~0xFFFF` over
every handler in the file) is where both numbers show up.  Seventeen origins were tested,
three produced tables, one won.

## 2. A stack pointer that looked like a bug

```json
{
 "kind": "cortex-m.vector_table",
 "subject": "table@0x08020000",
 "confidence": 0.865,
 "summary": "vector table at 0x08020000: 115 live handlers within 150 scanned slots (10 zeroed, 25 non-code), initial MSP 0x00004000, reset handler 0x080201F9; 78 distinct targets, unused slots are aliased to a default handler; the scan stopped after 24 unused slots, so the live count is a lower bound",
 "metrics": {
  "msp": "0x00004000", "reset": "0x080201F9", "n_live": 115, "n_scanned": 150,
  "unique_handlers": 78, "monotone_ratio": 0.544, "slot_density": 0.767
 }
}
```

`0x00004000` is not in any RAM region this tool knew about.  The first version of the
ranking said **"MSP outside every declared RAM region"** and applied a penalty — to the
*correct* candidate.  Which is how the F4/F7 comparison got reported as if the F4 had won
on evidence.

The fix was not to relax the check.  `0x00004000` is exactly `0x0000_0000 + 16 KB`, and
ST's own header says what lives there:

```c
/* socdb-src/stm32f765xx.h, line 1205 */
#define RAMITCM_BASE  0x00000000UL  /*!< Base address of : 16KB RAM reserved for CPU
                                       execution/instruction accessible over ITCM */
```

An initial stack pointer at the **top of a 16 KB RAM window** is not an anomaly, it is
`_estack`.  The map was wrong because the generator only keeps base defines that name a
peripheral, so `RAMITCM_BASE` never reached `ram_bases()` — the fact was in the header and
got dropped on the way in.  The window therefore had to be re-added, in a form that cannot
leak into the wrong family:

```python
ITCM_ALIAS   = (0x0000_0000, 0x0001_0000)   # 64 KB: the largest ITCM either header claims
ITCM_CORES   = ("cortex-m7", "cortex-m55", "cortex-m85")

def itcm_base(self) -> int | None:
    if self.core in ITCM_CORES and 0x2000_0000 in self.ram_bases():
        return ITCM_ALIAS[0]          # 0x0000_0000
    return None
```

`stm32h743xx.h` declares the same window as 64 KB (`D1_ITCMRAM_BASE`), so the bound is the
larger of the two and `0x0001_0000` stops there.  On a Cortex-M4 the low window is the
*flash* alias: the same `0x00004000` there means a bogus stack pointer, so accepting it
would let a broken value vouch for a part.  `tests/test_socdb.py` pins both halves — F7
accepts, F4 refuses, and the window closes at 64 KB.  The top candidate in the JSON report,
summary verbatim:

```json
{
  "kind": "soc.candidate",
  "subject": "stm32f765xx",
  "confidence": 0.757,
  "summary": "best match: stm32f765xx: 97 distinct device constants in this image land in its peripheral map (88 blocks), 4 of them in no other installed map, and 1 that another map explains are missing from it; load region inside flash base 0x08000000; MSP inside RAM at 0x00000000 (ITCM)"
}
```

The plain-text table prints the same finding at two decimals (`0.76`) and truncates the
summary at the column; the JSON is the artifact to quote.

## 3. Four constants that separate the families

This is the part the F4 sample could not do.  The header line the scan prints:

```
candidates  stm32f765xx=97 constants/88 blocks, stm32f427xx=90 constants/81 blocks, stm32h743xx=49 constants/42 blocks
```

and the three `soc.candidate` findings behind it, straight from the JSON:

| map | conf | constants explained | blocks | `exclusive_constants` | `blind_constants` |
|---|---|---|---|---|---|
| stm32f765xx | 0.757 | 97 | 88 | **4** | 1 |
| stm32f427xx | 0.58 | 90 | 81 | 0 | 8 |
| stm32h743xx | 0.433 | 49 | 42 | 1 | 49 |

The F4 map is *blind* to eight constants this image contains, and the F7 map explains all
eight.  Four of them belong to no other installed map:

| constant | F765 block | register the CMSIS struct names | present on F427? |
|---|---|---|---|
| `0x4000_6000` | I2C4 | CR1 | no — F4 has three I2C |
| `0x4001_1C00` | SDMMC2 | POWER | no — single SDMMC on F427 |
| `0x4001_7800` | MDIOS | (block base) | no — Manageable Data I/O is F7-era |
| `0xA000_1000` | QSPI_R | CR | no — F427 has no quad-SPI |

Each one is a 32-bit word that is physically in the dump, in a peripheral window the F4
header does not define at all.  *That* is the evidence the ranking wants — and it is also
the answer to the obvious reviewer question, "is this just block-name matching with extra
steps?"  No: the F4 and F7 maps both contain a block called `PWR`, at `0x40007000` in each.
Counting names would call those candidates tied.  Counting *addresses* puts eight
constants on the F7's side of the ledger.

The blind side matters as much as the exclusive side, and it caught a real trap.  The one
constant the F7 map cannot explain, `0x52002020`, is what makes `stm32h743xx` look
*slightly* distinctive on both samples — and on the F4 sample it turns out to be four
bytes of the ASCII string `"R0    "` from the HardFault dump
([case-openmv2.md](case-openmv2.md) §3).  Exclusivity without blindness would have made an
H7 a contender for both boards.

## 4. What the code touches, and what it is not

```
peripheral.access  RCC     0.86  RCC: 265 decoded load/store(s) through a tracked base
                                 register; DCKCFGR2/read=25, AHB1ENR/read=23, …
peripheral.access  DMA1    0.86  DMA1: 26 decoded load/store(s) through a tracked base
                                 register; HIFCR/write=13, LIFCR/write=13
peripheral.access  FLASH_R 0.86  FLASH_R: 62 decoded load/store(s) …; CR/read=21,
                                 CR/write=20, ACR/…
peripheral.usage   GPIOA   0.82  GPIOA @0x40020000 referenced 22 times as an address
                                 constant; registers seen: MODER(22)
```

`DCKCFGR2` is the register that does not exist on the F4 at all: its RCC struct ends at
`DCKCFGR` (25 fields), the F7's continues to `DCKCFGR1` and `DCKCFGR2`.  The name came out
of the database, not out of a pattern the tool memorised.
`HIFCR/write=13, LIFCR/write=13` on both DMA controllers is the interrupt-flag clear
pattern; the direction is a decoded `STR`, not an assumption.

Eighty-eight peripheral blocks carry address evidence in this run, 117 findings in total,
0 contract violations.  Two of the rows are deliberately *not* presented as peripherals:

```
memory.reference  RAMDTCM   RAMDTCM @0x20000000 referenced 26 times as an address
                            constant; no CMSIS register struct: this is a memory or
                            bit-band window, so no register names are claimed
memory.reference  UID       UID @0x1FF0F420 referenced 1 time as an address constant
```

`UID` — the 96-bit device identifier — is a *place*, and `carve/1` proves the word is in
the image.  Reading it needs code that runs, so the row claims membership of a memory
region and nothing about what was read from it.

## 5. The counter-evidence, reported anyway

```
soc.coverage  stm32f765xx  0.45  14 device address(es) reached by decoded instructions
                                  are not in stm32f765xx's map (42 accesses, e.g.
                                  0x40012304, 0x80000002, 0xB60B60B7, 0x40025FC4,
                                  0x40025FD8, 0x46314640); no other installed map names
                                  them either, so this is a hole in the databases or a
                                  vendor block CMSIS does not define, not evidence of a
                                  wrong part
```

Look at `0xB60B60B7`.  No SoC has that block, and the row is still allowed to exist,
because the honest reading of "an instruction computed this number" is that the *pairing*
of a `MOVW` with a `MOVT` was guessed wrong by a flow-insensitive scan — the note says so
rather than promoting it to hardware.  `0x40012304` is more interesting than the junk.  The F7 map has a block at
`0x4001_2300` — the shared ADC front end — and CMSIS gives that struct exactly **4 bytes**,
so offset `+4` is one word past a hole in ST's own header.  Code really did reach it
(`str` with a tracked base), the block really is ADC, and the register has no name.
That is a gap in the database, not a wrong part, which is why the row sits at 0.45 and
says so.  The same rule covers `MDIOS @0x40017800` in §4, reported as `(block base)`
instead of an invented register.

The number that would actually threaten the match is `contested: 0`: not one of those 14
addresses is a block another installed map *does* name.  A non-zero value there is the
tool telling you the wrong family is in the running, and it is the reason the confidence
on this row would jump to 0.6 rather than stay at 0.45.

## 6. Cross-checks

**The linker.** 15 driver families in `firmware.elf`'s symbol table, 15 found:

```
$ firmprint verify samples/openmv3/firmware.elf
- matched part stm32f765xx; 88 peripheral block(s) with address evidence;
  194,240 instructions decoded
- oracle: 15 driver module(s) named by the image's own symbols
- confirmed 15/15 (recall 100%) over driver-linked peripherals
contract: 0 violation(s)
```

I2C (32 linked symbols), TIM (31), SPI (24), DCMI (14), DMA2D (10), DMA (7), RCC (6),
ADC/CAN/RTC (5 each), GPIO (4), FLASH/PWR/CRC (3 each), UART (2).  RTC's row is confirmed
by `carve/1` alone — the constant is there, the decoded access was not reached inside the
byte budget, and the report keeps that distinction instead of rounding it up.  33 blocks
were reported that the oracle cannot name (SAI2, SPDIFRX, MDIOS, LPTIM1, QSPI_R, the DMA
streams, ETH, CAN3…); not counted as false positives, because the oracle is blind to
direct register writes, and every one carries its own offsets.

**The build banner.** `; OPENMV3 with STM32F765` at `0x0817A666`, plus `OpenMV3-M7` —
strings embedded by OpenMV's own build system, independent of every address heuristic in
this document.

**The merged image.** `openmv.bin` carries both halves, and the scan reports both:

```
table@0x08020000  conf 0.865  115 live  MSP 0x00004000  reset 0x080201F9   (application)
table@0x08000000  conf 0.764  115 live  MSP 0x20005848  reset 0x080042B9   (bootloader)

container note: more than one vector table: this is probably a merged image
                (bootloader + application) or a dump that contains a RAM copy of
                the table; the scan reports each one separately
```

`bootloader.elf` — the same bootloader, shipped with its symbols — has ELF entry
`0x080042B9`.  The inferred second table's reset handler equals it exactly.  Note also
what the bootloader scan says about the *part*: `? stm32f427xx … conf 0.58  no installed
map is distinctive here`.  A 23 KB bootloader that touches 17 peripheral constants cannot
be pinned by this method, and the tool prints the `?` and the phrase rather than choosing
one.

**The metadata removed.** ELF run and raw run agree on the part and report the same 88
peripheral blocks; `verification/openmv3.md` §2 checks that automatically.

## 7. What this sample is really for

The F765 case looks like the easy win — right part, 15/15, a clean four-constant margin.
It is the harder one.  It produced a wrong RAM judgement that quietly demoted the correct
map, it produced an "exclusive constant" that turned out to be ASCII, and it produced 42
decoded accesses to addresses no vendor map names.  All three are in the tool now as
*published numbers with a rule attached*, because the only version of this story worth
putting in a repository is the one where the sample was allowed to disagree with the
answer.

## Reproduce

```bash
pip install -e ".[capstone]"
python tools/get_sample.py --board OPENMV3
firmprint scan samples/openmv3/firmware.bin
firmprint scan samples/openmv3/openmv.bin
firmprint scan samples/openmv3/bootloader.elf
firmprint verify samples/openmv3/firmware.elf
python tools/make_verification.py openmv3     # rewrites verification/openmv3.md
```
