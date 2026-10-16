# Verification: openmv3 (STM32F765VGT6)

A reverse-engineering tool that outputs confident prose is easy to dismiss, so this
repository ships an answer key instead of a promise.  Every number below was produced
by `python tools/make_verification.py openmv3` against MIT-licensed OpenMV firmware —
no figure is typed in by hand.

- image: `firmware.elf`, 10,464,140 bytes, sha256 `c3907f8c1def1c1ba1d3699c7218a9730043f96298c9cd86cc5d50c19c8b38f7`
- vendor part: **STM32F765VGT6**, confirmed by the banner string the build embedded: `OPENMV3 with STM32F765`
- firmprint answer: **stm32f765xx** (f7, cortex-m7) from `STMicroelectronics/cmsis-device-f7` header sha256 `31fb8b970e795b41...`
- evidence-contract violations: **0**

## 1. Do the peripheral claims match reality?

The oracle is the image's own symbol table: ST's Hardware Abstraction Layer links one
`HAL_<MODULE>_*` family per driven peripheral, so the linker says which peripherals have
driver code present.  firmprint never sees that mapping as input — it reads 32-bit
constants and Thumb-2 instructions and derives blocks from addresses.

- instructions decoded: 194,240 (32% of code, 2374 functions)
- driver-linked modules: **15**, confirmed by firmprint: **15/15** (recall 100%)

| oracle module | linked symbols | firmprint block(s) | status | engine(s) |
|---|---|---|---|---|
| I2C | 32 | I2C1, I2C2, I2C3, I2C4 | OK | capstone/5.0.9, carve/1 |
| TIM | 31 | TIM1, TIM2, TIM3, TIM4, TIM5, TIM6, TIM7, TIM8, TIM9, TIM10, TIM11, TIM12, TIM13, TIM14 | OK | capstone/5.0.9, carve/1 |
| SPI | 24 | SPI1, SPI2, SPI3, SPI4, SPI5, SPI6 | OK | capstone/5.0.9, carve/1 |
| DCMI | 14 | DCMI | OK | capstone/5.0.9, carve/1 |
| DMA2D | 10 | DMA2D | OK | capstone/5.0.9, carve/1 |
| DMA | 7 | DMA1, DMA2 | OK | capstone/5.0.9, carve/1 |
| RCC | 6 | RCC | OK | capstone/5.0.9, carve/1 |
| ADC | 5 | ADC1, ADC2, ADC3 | OK | capstone/5.0.9, carve/1 |
| CAN | 5 | CAN1, CAN2 | OK | capstone/5.0.9, carve/1 |
| RTC | 5 | RTC | OK | carve/1 |
| GPIO | 4 | GPIOA, GPIOB, GPIOC, GPIOD, GPIOE, GPIOF, GPIOG, GPIOH, GPIOI, GPIOJ, GPIOK | OK | capstone/5.0.9, carve/1 |
| FLASH | 3 | FLASH_R | OK | capstone/5.0.9, carve/1 |
| PWR | 3 | PWR | OK | capstone/5.0.9, carve/1 |
| CRC | 3 | CRC | OK | capstone/5.0.9, carve/1 |
| UART | 2 | USART1, USART2, USART3, UART4, UART5, USART6 | OK | capstone/5.0.9, carve/1 |

Peripheral blocks firmprint reported that the driver oracle has no name for (33): ADC, CAN3, CEC, DAC, DBGMCU, DMA1_Stream0, DMA1_Stream2, DMA1_Stream3, DMA1_Stream4, DMA1_Stream5, DMA1_Stream6, DMA1_Stream7, DMA2_Stream1, DMA2_Stream3, DMA2_Stream5, DMA2_Stream6, ETH, EXTI, FMC_Bank1_R, IWDG, LPTIM1, MDIOS, QSPI_R, RNG, SAI1, SAI2, SDMMC1, SDMMC2, SPDIFRX, SYSCFG, UART7, UART8, WWDG

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

- inferred load base: **0x08020000** (true application link address: 0x08020000 — the app sits above a 128 KB bootloader)
- matched part: **stm32f765xx** — best match: stm32f765xx: 97 distinct device constants in this image land in its peripheral map (88 blocks), 4 of them in no other installed map, and 1 that another map explains are missing from it
- every installed map, in rank order: stm32f765xx=97 constants/88 blocks (exclusive 4, blind 1, conf 0.757), stm32f427xx=90 constants/81 blocks (exclusive 0, blind 8, conf 0.58), stm32h743xx=49 constants/42 blocks (exclusive 1, blind 49, conf 0.433)
- peripheral blocks reported: 88 of the 88 the ELF run found
- byte-identical answer without metadata: **yes**


## 3. Two vector tables in one file

`openmv.bin` is the merged release image: a bootloader followed by the application.
Both halves carry a table, so a tool that reports one base for the file is wrong about
one of them.

| image | table | confidence | live handlers | slots | initial MSP | reset |
|---|---|---|---|---|---|---|
| firmware.elf | table@0x08020000 | 0.865 | 115 | 150 | 0x00004000 | 0x080201F9 |
| firmware.bin | table@0x08020000 | 0.865 | 115 | 150 | 0x00004000 | 0x080201F9 |
| openmv.bin | table@0x08020000 | 0.865 | 115 | 150 | 0x00004000 | 0x080201F9 |
| openmv.bin | table@0x08000000 | 0.764 | 115 | 150 | 0x20005848 | 0x080042B9 |

- merged image base inference: 0x08000000 (correct: the bootloader is at 0x08000000)
- what the inference said out loud: raw dump: no container header. load base inferred as 0x08000000: of the 17 origins tested it is the one whose best candidate reads most like a vector table (2 table(s) there, the first at file offset 0x0); origins that also produced tables: 0x08010000(1), 0x08020000(1). Pass --base to pin it.

## 4. What it refuses to claim

- it says `stm32f765xx`, not `STM32F765VGT6`: several part numbers share one peripheral
  map, and the map is what bytes determine.  Every candidate row keeps that in `unknowns`.
- here the ranking separated the family on evidence: the winning map explains
  4 device constant(s) no other installed map can see.  The identical test on
  the `openmv2` sample (verification/openmv2.md) explains 0, which is why
  that report says so instead of naming a part on a coin flip.
- the matched map is also judged on what it misses: 11 device address(es) reached by decoded instructions are not in stm32f765xx's map (39 accesses, e.g. 0x40012304, 0x80000002, 0xB60B60B7, 0x40025FC4, 0x40025FD8, 0x46314640); no other installed map na…
  (`soc.coverage`, confidence 0.45, contested addresses: 0)
- carving proves a constant is present, not that code executed an access: those rows are
  labelled `carve/1` and never claim a direction.  `peripheral.access` rows come only
  from the capstone engine and quote instruction bytes.
- register names resolve only where CMSIS gives the block a struct; an offset inside a
  struct hole reports as the block base rather than an invented register.
- runtimes: ELF 1.78s, raw 1.8s, merged 2.38s (3.12.10 / windows).

## Reproduce

```bash
pip install -e .[capstone]
python tools/get_sample.py --board OPENMV3   # MIT-licensed OpenMV firmware
python tools/make_verification.py openmv3      # rewrites this file
```

