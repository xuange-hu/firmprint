# Verification: openmv2 (STM32F427VGT6)

A reverse-engineering tool that outputs confident prose is easy to dismiss, so this
repository ships an answer key instead of a promise.  Every number below was produced
by `python tools/make_verification.py openmv2` against real OpenMV firmware —
no figure is typed in by hand.

- source: OpenMV release `v5.0.1`, asset `firmware_v5.0.1.zip` (sha256 `1338b9607b57d88cf1de5aee115ea0e18cb17d06ff4d8dc55d6c022dba66dbc8`), fetched by `python tools/get_sample.py --all`
- image: `firmware.elf`, 7,571,696 bytes, sha256 `e2f1cc135d32d733371f19a779fa0202e8a1b3d96ddc056d5e1601b24665e6f3`
- image: `firmware.bin`, 783,076 bytes, sha256 `7aa2b5364d124e3b5ae0d6595cb41b557bf32b646ab59201165dbe6a59e20a1e`
- image: `openmv.bin`, 848,612 bytes, sha256 `5bd1d1b26e5b0766816fd09faa914f8b63455f47b2a3517226c67ec59d12afa3`

Three views of the same board: the ELF carries symbols (the oracle reads them),
the raw flash image is what a confiscation bag actually contains, and the merged
release image is what OpenMV ships to the device.  `tools/get_sample.py` pins all
three by sha256, and the doc gate fails if the bytes on disk are not these.

- vendor part: **STM32F427VGT6**, confirmed by the banner string the build embedded: `OPENMV2 with STM32F427`
- firmprint answer: **stm32f427xx** (f4, cortex-m4) from `STMicroelectronics/cmsis-device-f4` header sha256 `eaffa1727f6308e9...`
- evidence-contract violations: **0**

## 1. Do the peripheral claims match reality?

The oracle is the image's own symbol table: ST's Hardware Abstraction Layer links one
`HAL_<MODULE>_*` family per driven peripheral, so the linker says which peripherals have
driver code present.  firmprint never sees that mapping as input — it reads 32-bit
constants and Thumb-2 instructions and derives blocks from addresses.

- instructions decoded: 202,077 (67% of code, 4017 functions)
- driver-linked modules: **14**, confirmed by firmprint: **14/14** (recall 100%)

| oracle module | linked symbols | firmprint block(s) | status | engine(s) |
|---|---|---|---|---|
| I2C | 32 | I2C1, I2C2, I2C3 | OK | capstone/5.0.9, carve/1 |
| TIM | 31 | TIM1, TIM2, TIM3, TIM4, TIM5, TIM6, TIM7, TIM8, TIM9, TIM10, TIM11, TIM12, TIM13, TIM14 | OK | capstone/5.0.9, carve/1 |
| SPI | 24 | SPI1, SPI2, SPI3, SPI4, SPI5, SPI6 | OK | capstone/5.0.9, carve/1 |
| DCMI | 14 | DCMI | OK | capstone/5.0.9, carve/1 |
| DMA2D | 10 | DMA2D | OK | capstone/5.0.9, carve/1 |
| DMA | 8 | DMA1, DMA2 | OK | capstone/5.0.9, carve/1 |
| RCC | 6 | RCC | OK | capstone/5.0.9, carve/1 |
| ADC | 5 | ADC1, ADC2, ADC3 | OK | capstone/5.0.9, carve/1 |
| CAN | 5 | CAN1, CAN2 | OK | capstone/5.0.9, carve/1 |
| RTC | 5 | RTC | OK | capstone/5.0.9, carve/1 |
| GPIO | 4 | GPIOA, GPIOB, GPIOC, GPIOD, GPIOE, GPIOF, GPIOG, GPIOH, GPIOI, GPIOJ, GPIOK | OK | capstone/5.0.9, carve/1 |
| PWR | 3 | PWR | OK | capstone/5.0.9, carve/1 |
| FLASH | 3 | FLASH_R | OK | capstone/5.0.9, carve/1 |
| UART | 2 | USART1, USART2, USART3, UART4, UART5, USART6 | OK | capstone/5.0.9, carve/1 |

Peripheral blocks firmprint reported that the driver oracle has no name for (28): ADC123_COMMON, CRC, DAC, DBGMCU, DMA1_Stream0, DMA1_Stream2, DMA1_Stream3, DMA1_Stream4, DMA1_Stream5, DMA1_Stream6, DMA1_Stream7, DMA2_Stream1, DMA2_Stream3, DMA2_Stream5, DMA2_Stream6, ETH, EXTI, FMC_Bank1_R, I2S2ext, I2S3ext, IWDG, RNG, SAI1, SDIO, SYSCFG, UART7, UART8, WWDG

Those are not counted as false positives: the oracle only knows about peripherals with a HAL/LL driver family in the symbol table, and direct register writes from application code are invisible to it. Each one still carries offsets and bytes.

contract: 0 violation(s)


A module counts as confirmed when *any* of its blocks shows up: that is the lenient
reading of recall.  It answers "did the tool find driver-bearing hardware", not "did
it find every instance", and per-block precision is not measurable against this oracle,
because a linked-but-unused driver and a direct register write look the same to it.

## 2. Does it work with the metadata removed?

`firmware.bin` is the same flash with the ELF wrapper stripped: no section headers, no
program headers, no symbol table.  The instruction engine cannot name functions and the
oracle is unavailable, so what survives is the part that matters for a real dump.

- inferred load base: **0x08010000** (true application link address: 0x08010000 — the app sits above a 64 KB bootloader)
- matched part: **stm32f427xx** — best match on the RAM map, not on device constants: stm32f427xx: 89 distinct device constants in this image land in its peripheral map (81 blocks), 0 of them in no other installed map, and 1 that another map explains are missing from it
- every installed map, in rank order: stm32f427xx=89 constants/81 blocks (exclusive 0, blind 1, conf 0.66), stm32f765xx=89 constants/81 blocks (exclusive 0, blind 1, conf 0.58), stm32h743xx=45 constants/39 blocks (exclusive 1, blind 45, conf 0.433)
- peripheral blocks reported: 81 of the 81 the ELF run found
- byte-identical answer without metadata: **yes**


## 3. Two vector tables in one file

`openmv.bin` is the merged release image: a bootloader followed by the application.
Both halves carry a table, so a tool that reports one base for the file is wrong about
one of them.

| image | table | confidence | live handlers | slots | initial MSP | reset |
|---|---|---|---|---|---|---|
| firmware.elf | table@0x08010000 | 0.855 | 98 | 131 | 0x1000F948 | 0x080101AD |
| firmware.bin | table@0x08010000 | 0.855 | 98 | 131 | 0x1000F948 | 0x080101AD |
| openmv.bin | table@0x08010000 | 0.855 | 98 | 131 | 0x1000F948 | 0x080101AD |
| openmv.bin | table@0x08000000 | 0.734 | 98 | 131 | 0x100057F0 | 0x08004215 |

- merged image base inference: 0x08000000 (correct: the bootloader is at 0x08000000)
- what the inference said out loud: raw dump: no container header. load base inferred as 0x08000000: of the 16 origins tested it is the one whose best candidate reads most like a vector table (2 table(s) there, the first at file offset 0x0); origins that also produced tables: 0x08010000(1); 11 of the 20 origins its own handler words proposed were not shape-tested, a cap on work and not a verdict on them. Pass --base to pin it.

## 4. What it refuses to claim

- it says `stm32f427xx`, not `STM32F427VGT6`: several part numbers share one peripheral
  map, and the map is what bytes determine.  Every candidate row keeps that in `unknowns`.
- here no map has exclusive constants, so the report names the closest installed
  map at reduced confidence and says the databases cannot separate these parts.
- the matched map is also judged on what it misses: 29 device address(es) reached by decoded instructions are not in stm32f427xx's map (65 accesses, e.g. 0x40012304, 0x40025FC4, 0x40025FD8, 0x42470000, 0x42470060, 0x40003840); 1 of them ARE in stm32h743xx (most under stm32h743xx) - another installed map sees hardware this one does not
  (`soc.coverage`, confidence 0.6, contested addresses: 1)
- carving proves a constant is present, not that code executed an access: those rows are
  labelled `carve/1` and never claim a direction.  `peripheral.access` rows come only
  from the capstone engine and quote instruction bytes.
- register names resolve only where CMSIS gives the block a struct; an offset inside a
  struct hole reports as the block base rather than an invented register.
- this document is generated, and re-running the generator has to leave it byte-identical:
  every number in it is a property of the image and of this tool.  Wall-clock timings and
  the interpreter that produced them used to be printed here, which made "no diff" true
  on one machine only; they are reported on stdout instead.

## Reproduce

```bash
pip install -e .[capstone]
python tools/get_sample.py --board OPENMV2   # real OpenMV firmware, see NOTICE.md
python tools/make_verification.py openmv2      # rewrites this file
```

