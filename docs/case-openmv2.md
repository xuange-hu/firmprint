# Case 1 — an OpenMV2 dump, with nothing told to the tool

The STM32F427 is the friendlier of the two samples, and the more instructive: it is the
one where the correct answer is *partly "I cannot tell you"*.  Every number here comes
from a command in this repository, run against a file the tool was never told anything
about.

```bash
python tools/get_sample.py --board OPENMV2   # 6 files, pinned by sha256
```

We will scan `firmware.bin`: 790,416 bytes, sha256 `7b7fca163c0a266f…`.  It is the
application half of OpenMV2's flash, and it carries **no** ELF wrapper, no section
headers, no program headers, no symbol table, and no link address.  A `strings`-and-grep
pass on it finds nothing that says "STM32".

---

## 1. Where does it run from?

```
$ firmprint scan samples/openmv2/firmware.bin
file        firmware.bin  790,416 B  sha256:7b7fca163c0a266f
container   raw / arm  1 segment(s)  entry -
            raw dump: no container header. load base inferred as 0x08010000: of the 16
            origins tested it is the one whose best candidate reads most like a vector
            table (1 table(s) there, the first at file offset 0x0); origins that also
            produced tables: 0x08000000(1). Pass --base to pin it.
```

The base is not looked up and not guessed from a linker script — it is *proposed by the
image itself*.  A Cortex-M vector table holds absolute code addresses, and every handler
in a flash-resident image has its own link address in its high bits, so the reset targets
in the file vote for candidate origins (`reset & ~0xFFFF`).  Sixteen candidates were
tested; two of them produced a table; `0x08010000` produced the best-shaped one, at file
offset 0x0.

The true application link address for an OpenMV2 build is `0x08010000`: the firmware sits
above a 64 KB USB bootloader at `0x08000000`.  The inference is right, and the report
names the runner-up instead of hiding it.

## 2. The vector table

```json
{
 "kind": "cortex-m.vector_table",
 "subject": "table@0x08010000",
 "confidence": 0.849,
 "rule": "cortex-m.vector_table.shape",
 "engine": "vectors/1",
 "summary": "vector table at 0x08010000: 98 live handlers within 131 scanned slots (8 zeroed, 25 non-code), initial MSP 0x1000F958, reset handler 0x080101AD; 76 distinct targets, unused slots are aliased to a default handler; the scan stopped after 24 unused slots, so the live count is a lower bound",
 "evidence": [
  {"kind": "bytes", "note": "initial MSP + reset vector (little endian)",
   "file_offset": 0, "vaddr": "0x08010000", "bytes": "58f90010ad010108"},
  {"kind": "bytes", "note": "following handler entries",
   "file_offset": 8, "vaddr": "0x08010008",
   "bytes": "532407084124070855240708652407087524070800000000"}
 ]
}
```

Read the evidence byte string as two little-endian words: `0x1000F958` and `0x080101AD`.
The first is where the stack starts — inside the F4's *CCM* RAM at `0x10000000`, not the
main SRAM at `0x20000000`, which is exactly what an ST application using the DMA-capable
`0x2000` SRAM plus CCM would do.  The second is the reset handler.

Three things in that summary are load-bearing:

- **98 of 131 slots are live**, and 25 scanned entries were rejected as non-code.  A
  shape rule (aligned, monotone, in-image, bounded gap) is what separates a table from
  131 consecutive 32-bit numbers.
- **Unused slots are aliased to a default handler** (`0x08010209` repeats) rather than
  zeroed.  Vendor choice, and a hint about the build, but not a part number.
- **The live count is a lower bound.**  The scan stops after 24 consecutive unused slots,
  and the summary says so.  A tool that reported "131 vectors, done" would be inventing
  the tail.

## 3. Which part — and where the answer is not "a part"

```
match       stm32f427xx (f4, cortex-m4)  conf 0.66  best match on the RAM map, not on device constants
            db STMicroelectronics/cmsis-device-f4@eaffa1727f63
candidates  stm32f427xx=89 constants/81 blocks, stm32f765xx=89 constants/81 blocks,
            stm32h743xx=45 constants/39 blocks
```

This dump contains 89 distinct 32-bit words that land inside the STM32F427 peripheral
map.  It contains *the same 89* inside the STM32F765 map.  Zero of them are visible to one
map and invisible to the other — the F4 and the F7 share their peripheral windows almost
entirely, so **no constant in this file can separate them**.  The report says that in the
match line itself, not in a footnote.

What does separate them is the memory *organisation*: the initial MSP `0x1000F958` sits
inside an F4 CCM window (`0x10000000`) that the F7's CMSIS header does not declare, and
the tie is broken there — with a 0.66 confidence and this caveat attached:

```
unknowns  the peripheral constants in this image are identical under another installed
          map, so this ranking rests on the RAM declaration alone and one vector-table
          entry count would overturn it
```

For contrast, the same test on the OpenMV3 sample separates the families on four
exclusive constants and reaches 0.76 — see [case-openmv3.md](case-openmv3.md).  Two
boards, two honest answers, no hand-picked win.

The third row is also instructive.  `stm32h743xx` explains 45 of the 89 and owns exactly
one constant the others cannot see, `0x52002020`, which its map calls `FLASH_R + 0x20`
(`OPTSR_PRG`).  Go looking: at file offset `0x98D18` those four bytes are `20 20 00 52` —
the tail of the ASCII string `"R0    "` inside the HardFault register dump

```
… \x00HardFault\r\n\x00R0    \x00R1    \x00R2    \x00R3    \x00R12   \x00SP    \x00LR
```

which is the only kind of thing that can make a memory map "exclusive" in a blob of mixed
code and data: four bytes of a crash-print string that happen to fall in another chip's
flash register window.  Exclusivity alone would have made an H7 a contender here; the
ranking uses exclusivity *and* the 45 constants it cannot see, and it still ranked H7
third at 0.433.

## 4. What the code actually touches

107 findings, of which 93 carry peripheral evidence.  The 11 `peripheral.access` rows are
the strong ones, because each quotes a decoded instruction:

```
peripheral.access  RCC   0.86  RCC: 182 decoded load/store(s) through a tracked base
                               register; AHB1ENR/read=21, APB1ENR/read=18, CFGR/read=18,
                               CR/read=16, AHB1ENR/write=11, CR/write=10, CFGR/write=10,
                               APB1ENR/write=10

  evidence  0x080101AE  ldr r3, [r0]  [read]  reached 0x40023830 -> RCC+0x030 (AHB1ENR)
            file offset 430, bytes 0368
```

`0x080101AE` is the second instruction of the reset handler (`0x080101AD` has the Thumb
bit set): this is clock startup, and it is the first thing the firmware does.  The register
name and the direction both come from the CMSIS struct in the database, not from a pattern
the tool memorised.

```
peripheral.access  DCMI  0.86  DCMI: 6 decoded load/store(s) through a tracked base
                               register; CR/read=4, CR/write=2
  evidence  0x080465AC  ldr r2, [r3]  [read]  reached 0x50050000 -> DCMI+0x000 (CR)
```

That one matters more than it looks.  `0x5005_0000` is the F4's camera interface, sitting
in the AHB2 peripheral window — an address a *whole class* of heuristics never sees,
because the usual shortcut is "constants near 0x4000_0000 are peripherals".  Here a base
register was tracked through a literal pool into an `LDR` from `[r3]`, and the block
resolved to `DCMI+0x000 (CR)` at `0x080465AC`, 217 KB into the dump.

The 81 `peripheral.usage` rows are the weaker, stdlib-only tier:

```
peripheral.usage  GPIOE  0.82  GPIOE @0x40021000 referenced 24 times as an address
                               constant; registers seen: MODER(24)
```

`carve/1` proves the constant `0x40021000` is *in the image*.  It does not prove code
executed an access, so the row never claims a direction, and the engine label is part of
the finding rather than a footer.  `--no-code` gives you exactly these 81 and nothing else.

## 5. What the report refuses to claim

```
soc.coverage  stm32f427xx  0.45  27 device address(es) reached by decoded instructions
                                  are not in stm32f427xx's map (61 accesses, e.g.
                                  0x40012304, 0x40025FC4, 0x40025FD8, 0x42470060, …);
                                  no other installed map names them either, so this is a
                                  hole in the databases or a vendor block CMSIS does not
                                  define, not evidence of a wrong part
```

The matched map is scored on its *misses*, not just its hits — and a miss is only allowed
to threaten the match when another installed map names the same address.  Here none does,
so the row is filed as a coverage gap.  It also shows the tool knowing when it has been
had: `0x42470060` is not a peripheral on any STM32; it is a mispaired `MOVW`/`MOVT`, and
the `unknowns` say that rather than listing it as hardware.

The other refusals in this run: one high-entropy block at `0x080B7000` (7.996 bits/byte)
reported as "encrypted or compressed payload" with the caveat that entropy cannot
distinguish TLS-terminated OTA from plain deflate; and 49 strings that read as identity
hints, led by `0x080A6619` — `; OPENMV2 with STM32F427`.

## 6. Cross-checks, from evidence the tool did not produce

**The linker.**  `firmware.elf` is the same flash with its symbol table intact, so
`firmprint verify` can score the peripheral claims against ST's HAL: one `HAL_<MODULE>_*`
family per driven peripheral, decided at link time, never given to firmprint as input.

```
$ firmprint verify samples/openmv2/firmware.elf
- matched part stm32f427xx; 81 peripheral block(s) with address evidence;
  202,041 instructions decoded
- oracle: 14 driver module(s) named by the image's own symbols
- confirmed 14/14 (recall 100%) over driver-linked peripherals
…
contract: 0 violation(s)
```

I2C, TIM, SPI, DCMI, DMA2D, DMA, RCC, ADC, CAN, RTC, GPIO, PWR, FLASH, UART — every
peripheral the linker says has a driver in this image was found from addresses.  28
further blocks were reported that the oracle has no name for (ETH, SDIO, RNG, SAI1, the DMA
streams, CRC, DAC…); those are *not* counted as false positives, because the oracle is
blind to direct register writes, and each row still carries its own offsets and bytes.

**The build banner.**  `; OPENMV2 with STM32F427` at `0x080A6619` — embedded by OpenMV's
own build, naming the part.  Independent of every address heuristic above.

**The bootloader.**  `bootloader.elf` has a real ELF entry point: `0x08004215`.  Scan the
merged release image and the tool finds two vector tables in one file:

```
$ firmprint scan samples/openmv2/openmv.bin
table@0x08010000  conf 0.849  98 live handlers  MSP 0x1000F958  reset 0x080101AD
table@0x08000000  conf 0.734  98 live handlers  MSP 0x100057F0  reset 0x08004215
```

The second reset handler equals the bootloader's entry point, and the base inference
picked `0x08000000` for the merged file — the address of the *bootloader*, which is the
right answer for a file whose first byte is the bootloader's stack pointer.  A tool that
reports one base per file is wrong about one of these halves; this one reports both.

**The metadata removed.**  The ELF run and the raw run produce the same 81 peripheral
blocks and the same part answer, with byte-level equality of the findings that do not need
symbols — `verification/openmv2.md` §2 checks that automatically.

## 7. What a human would do next

The tool stops at "F427-class, map-tied with F765, RAM says F4".  Closing the last step
needs something outside a stripped dump, in rough order of cost:

1. `DBGMCU_IDCODE` (`0xE0042000`) — if the dump is from a live device, this answers the
   part number exactly.  In this image the register block is referenced, not readable.
2. Vector-table length: the F427 and F765 tables differ in entry count, but a dump stops
   where the gaps start, so this is corroboration, not proof.
3. The option bytes and the `RCC` clock configuration for flash size and package hints —
   `VG` versus `ZG` is a pin-count question the peripheral map genuinely cannot answer.

That boundary — four minutes of tool output, then a named list of what only the hardware
can settle — is what the report is trying to give you.

## Reproduce

```bash
pip install -e ".[capstone]"
python tools/get_sample.py --board OPENMV2
firmprint scan samples/openmv2/firmware.bin
firmprint scan samples/openmv2/openmv.bin
firmprint verify samples/openmv2/firmware.elf
python tools/make_verification.py openmv2     # rewrites verification/openmv2.md
```
