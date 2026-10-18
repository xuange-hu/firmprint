# firmprint

[![ci](https://github.com/xuange-hu/firmprint/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/firmprint/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.12-blue)
![dependencies](https://img.shields.io/badge/runtime%20dependencies-0-informational)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Firmware identification that shows its work.**

`firmprint` takes a Cortex-M firmware image — an ELF, a raw `.bin` dump pulled off a
flash chip, an Intel HEX, or a merged bootloader+application image — and answers three
questions a reversing session always starts with:

1. **What chip is this, and how sure are you?** Ranked SoC candidates, each with the
   number of device constants its memory map explains, the number *no other installed
   map* can explain, and the counter-evidence against it.
2. **Where does it run from?** Container parse, or load-base inference for a headerless
   dump, validated by the image's own vector table.
3. **What hardware does the code actually touch?** Peripheral blocks with register names
   and read/write direction, from carved constants (no dependencies) or from decoded
   Thumb-2 instructions (with [capstone](https://www.capstone-engine.org/)).

Every claim in the report carries the file offset, the virtual address and the raw bytes
that produced it, and the report states what it could **not** establish. A confident
claim with no anchored evidence is a *contract violation*, and the tool fails closed on
those instead of printing them.

```
$ firmprint scan samples/openmv2/firmware.bin
file        firmware.bin  790,416 B  sha256:7b7fca163c0a266f…
container   raw / arm  1 segment(s)  entry -
            raw dump: no container header. load base inferred as 0x08010000: of the 16 origins
            tested it is the one whose best candidate reads most like a vector table (1 table(s)
            there, the first at file offset 0x0); origins that also produced tables: 0x08000000(1).
            Pass --base to pin it.
match       stm32f427xx (f4, cortex-m4)  conf 0.66  best match on the RAM map, not on device constants
            db STMicroelectronics/cmsis-device-f4@eaffa1727f63…
candidates  stm32f427xx=89 constants/81 blocks, stm32f765xx=89 constants/81 blocks, stm32h743xx=45 constants/39 blocks
engines     container=container/1, vectors=vectors/1, carve=carve/1, decode=capstone/5.0.9
decoded     200,010 instructions, 0 function(s), coverage 66%
contract    0 violation(s)

kind                    subject              conf  summary
----------------------------------------------------------------------------------------------------
cortex-m.vector_table   table@0x08010000     0.85  vector table at 0x08010000: 98 live handlers within 131 scanned slots (8 zeroed, 25 non-code), ...
peripheral.access       RCC                  0.86  RCC: 182 decoded load/store(s) through a tracked base register; AHB1ENR/read=21, APB1ENR/read=18 ...
memory.reference        CCMDATARAM           0.82  CCMDATARAM @0x10000000 referenced 41 times as an address constant; no CMSIS register struct ...
soc.candidate           stm32f427xx          0.66  best match on the RAM map, not on device constants: stm32f427xx: 89 distinct device constants ...
```

*(One row per `kind`, trimmed at the column; every line is verbatim from that run. Plain
text caps the table at 30 findings, so `soc.candidate` only shows up with
`--max-findings` or in `--json`.)*

That dump has no symbol table, no section headers and no link address in it. The tool
inferred `0x08010000` (the true application base, sitting above a 64 KB bootloader) and
named the part — and then said out loud that the *peripheral constants alone do not*
separate an STM32F427 from an STM32F765, because those two families share their
peripheral windows almost entirely. That sentence is the reason this project exists.

---

## Install

```bash
pipx install git+https://github.com/xuange-hu/firmprint.git    # or: pip install .
```

Zero required dependencies — the whole stdlib path (container parsing, vector-table
shaping, constant carving, memory-map ranking, JSON/Markdown reports, the MCP server)
runs on a Python 3.10+ install with nothing else on the machine. Useful on an incident
box where `pip install` is having a day. Once the first tag is published the same thing
is `pipx install firmprint`.

```bash
pip install "firmprint[capstone]"     # adds real Thumb-2 decoding: register names,
                                      # read/write direction, function-level evidence
```

Without capstone the scan still works and the report *says* it degraded:

```
note: capstone not installed → register-level access not attempted (address carving only)
```

From a checkout:

```bash
git clone https://github.com/xuange-hu/firmprint && cd firmprint
pip install -e ".[dev]"
python tools/make_synthetic.py blob.bin   # a shaped Cortex-M image: no download, no key
firmprint scan blob.bin --strict          # the dependency-free path still answers
python tools/get_sample.py --all          # 2 MIT-licensed OpenMV images, pinned by sha256
python -m pytest -q                       # 287 tests, no network
```

## 30-second tour

```bash
firmprint scan firmware.elf                       # an ELF: segments, symbols, names
firmprint scan dump.bin --base 0x08000000         # a raw dump, link address pinned by you
firmprint scan dump.bin                           # ... or inferred, with the reasoning printed
firmprint scan app.hex --json report.json --md report.md
firmprint scan dump.bin --soc stm32h743xx         # stop ranking, use this map
firmprint scan dump.bin --full                    # decode every code byte, no budget
firmprint verify firmware.elf                     # score findings against the image's own symbols
firmprint verify firmware.elf --strict            # and fail a run whose own contract is broken
firmprint socdb list                              # installed maps + the vendor header each came from
firmprint mcp --self-test                         # check the MCP server without a client
```

Exit codes are scriptable: `--strict` makes a non-empty evidence contract a failure on both
`scan` and `verify`, so a CI job or a triage pipeline can refuse an untrustworthy report.

## What makes it different

### 1. Evidence, or it is not a finding

Every `Finding` carries `kind`, `subject`, `confidence`, `engine`, `rule`, a list of
evidence records, and a list of `unknowns`.  This is the real report for
`samples/openmv2/firmware.elf`, trimmed to the first of its 9 evidence items:

```json
{
  "kind": "peripheral.access",
  "subject": "CAN1",
  "confidence": 0.86,
  "engine": "capstone/5.0.9",
  "rule": "peripheral.access.tracked-base-register",
  "evidence_total": 9,
  "evidence": [{
    "kind": "instruction",
    "note": "0x08018F00 ldr.w r0, [r3, #0x200]  [read]  in HAL_CAN_ConfigFilter  reached 0x40006600 -> CAN1+0x200 (FMR)",
    "file_offset": 40704,
    "vaddr": "0x08018F00",
    "bytes": "d3f80002",
    "text": "ldr.w r0, [r3, #0x200]"
  }],
  "unknowns": ["base-register tracking resets at function boundaries, so a base held across a branch is counted as unknown rather than guessed", "offsets are static; index registers and peripheral aliases are not resolved"]
}
```

`firmprint.evidence.validate()` is fail-closed: at or above confidence 0.6 a claim needs
evidence, and at least one item must name a *place* (a file offset or a virtual address).
An evidence list of floating prose is decoration, not proof, and the tool reports it as a
violation. So does the contract line at the top of every run.

Two engine tiers are kept apart on purpose, because collapsing them is how a tool turns
unsupported block references into claimed register accesses:

| tier | kind | what it can say |
|---|---|---|
| stdlib, no deps | `peripheral.usage`, `memory.reference` | this 32-bit word **is present** and lands in this block; no direction |
| capstone | `peripheral.access`, `peripheral.materialised` | this instruction **loaded or stored** through a tracked base register, at this offset, these bytes |

### 2. Ranking that reports its own blindness

Naive memory-map matching counts how many block *names* fit. That is a popularity
contest for whichever map has the most aliases — and it is how an STM32F7 image scores
"stm32f427xx, 81 blocks", because F4's GPIO/DMA windows sit exactly where F7's do.

`rank_socs` counts **distinct address constants** and reports three numbers per map:

- `constants_explained` — how much of the image's device evidence this map can see;
- `exclusive_constants` — how much of it *no other installed map* can see;
- `blind_constants` — how much another map explains that this one cannot.

Then it behaves differently depending on what those say:

- the F427-vs-F765 case: 89 constants each, **0 exclusive** → the top candidate is
  capped at 0.66 and prefixed `best match on the RAM map, not on device constants`,
  separated only by the initial stack pointer landing in CCM (`0x1000_0000`, a region
  the F4 declares and the F7 does not) — and the report says *that*, plus "one
  vector-table entry count would overturn it", in its `unknowns`;
- the F765-vs-H743 and F427 cases: an exclusive constant exists → `best match:`, 0.76;
- a single installed map, or a tie → the head becomes `no installed map is distinctive
  here`, capped at 0.58, instead of naming a part on a coin flip;
- and the map that *did* match is judged on what it missed: `soc.coverage` lists the
  device addresses decoded instructions reached that its map cannot name, and says
  whether another installed map can (contested: a threat to the match) or none can
  (a hole in the databases, not evidence of a wrong part).

### 3. The documentation is a test fixture

Every report line pasted in this README and in `docs/case-*.md` is compared against a live
scan of the real images in CI — and so is every number in a *sentence*, not just in a
transcript: that the ELF run decodes 202,041 instructions, that a table of 131 scanned slots
had 98 of them live, that the vector scan stops after 24 consecutive unused slots (that one
is read out of the code, so moving the constant without moving the prose fails the build).

`python tools/check_doc_quotes.py` re-scans every sample, rebuilds the synthetic image the
quickstart tells you to make, and refuses a document whose counts no run produces. A
heuristic tweak that moves a number has to move the sentence in the same commit.  A number
invented for rhetorical effect does not survive the gate — which is the point: the claim of
this tool is that a statement arrives with the evidence for it, and that includes statements
this repository makes about itself.

## Verification: an answer key, not a promise

`firmprint verify` scores findings against an oracle the tool never sees as input: an ST
image built with the Hardware Abstraction Layer links one `HAL_<MODULE>_*` function
family per driven peripheral, so the ELF's own symbol table says which hardware has
driver code.

Two real, MIT-licensed OpenMV boards, regenerated by `python tools/make_verification.py`:

| image | true part | firmprint said | driver oracle | contract | notes |
|---|---|---|---|---|---|
| OpenMV2 `firmware.elf` | STM32F427VGT6 | `stm32f427xx` | **14/14** confirmed | 0 | 202,041 instructions decoded |
| OpenMV2 `firmware.bin` (metadata stripped) | STM32F427VGT6 | `stm32f427xx` | n/a (no symbols) | 0 | base inferred `0x08010000` ✓, same 81 blocks as the ELF run |
| OpenMV3 `firmware.elf` | STM32F765VGT6 | `stm32f765xx` | **15/15** confirmed | 0 | 194,240 instructions decoded |
| OpenMV3 `firmware.bin` (metadata stripped) | STM32F765VGT6 | `stm32f765xx` | n/a | 0 | base inferred `0x08020000` ✓, separated on 4 exclusive constants |
| `openmv.bin` (merged bootloader + app) | both halves | 2 vector tables | n/a | 0 | tables at `0x08000000` **and** `0x08020000`, one file |

Full documents, every number machine-generated: [verification/openmv2.md](verification/openmv2.md) · [verification/openmv3.md](verification/openmv3.md)

What the oracle cannot measure is stated in the same documents: a linked-but-unused
driver and a direct register write look identical to it, so recall is reported over
driver-bearing modules and blocks with no oracle name are listed as *unconfirmed*, never
as false positives.

## Memory-map databases

The shipped maps are **generated from vendor CMSIS headers**, not typed in:

```
$ firmprint socdb list
stm32f427xx            f4   cortex-m4    117 blocks   30 structs  eaffa1727f63
stm32f765xx            f7   cortex-m7    135 blocks   35 structs  31fb8b970e79
stm32h743xx            h7   cortex-m7    270 blocks   55 structs  38dfcc42cfda
```

Each JSON records the source repo, the path inside it and the sha256 of the exact header
bytes it parsed. If a base address in a report is wrong, the mistake is traceable to one
upstream file — and anyone can regenerate the map from that file (`tools/gen_socdb.py`,
and a test asserts the shipped map is byte-reproducible from the cached header).

Add your own part in two commands:

```bash
python tools/gen_socdb.py fetch --family g0 --device stm32g071xx
python tools/gen_socdb.py build --family g0 --device stm32g071xx
firmprint scan dump.bin          # now ranks against four maps
```

Or point at a header you already have, no network:

```bash
firmprint build --header stm32h7a3xx.h --family h7 --device stm32h7a3xx
```

## Use it from an agent (MCP)

The analysis is the product; the MCP server is the same engine with a JSON-RPC front, so
a coding agent or a triage bot can call it and get structured, evidence-bearing replies
back. Read-only, no shell, no network.

```bash
firmprint mcp --self-test
# mcp self-test ok: 4 tools, 6 replies, protocol 2024-11-05
```

Register it with any MCP client (`claude_desktop_config.json`, `Cursor`/`Qoder` MCP
settings, Continue, Zed, or the official `mcp` Python SDK):

```json
{
  "mcpServers": {
    "firmprint": {
      "command": "firmprint",
      "args": ["mcp"]
    }
  }
}
```

| tool | what it returns |
|---|---|
| `firmprint_scan` | the full report: container, load base, SoC candidates, peripherals, `contract.violations` |
| `firmprint_verify` | confirmed/missed per driver module against the image's own symbols |
| `firmprint_socdb_list` | installed maps and their header provenance |
| `firmprint_socdb_show` | resolve one address → block + register, to re-check a report line |

Prompt idea that works well: *"scan this image, then for every `soc.candidate` with
`exclusive_constants == 0`, tell me what evidence would separate the parts."* The report
already contains that answer in `unknowns`, which is exactly the point — the model gets a
calibrated claim instead of a confident guess.

## How it works

```
bytes → container.py   ELF / PE-OTA sniff / Intel HEX / Motorola S-record / raw
        │              (+ DfuSe and compressed wrappers: detected and refused)
      → vectors.py     Cortex-M table shape test: alignment, MSP in RAM, handler
        │              targets inside code, "reset ≥ its own table", nesting killed
      → socdb.py       CMSIS-derived maps: block lookup, register offsets, RAM/flash windows
      → carve.py       32-bit constant carving, per distinct address, with counter-evidence
      → decode.py      optional capstone Thumb-2 sweep, register tracking, direction
      → evidence.py    the contract: strict claims need anchored evidence
      → analyze.py     one report: schema-stable JSON + Markdown
```

Design decisions worth stealing:

- **The shape test is the only authority.** A candidate origin is *proposed* by the
  image's own reset vectors (`reset & ~0xFFFF`) instead of a hard-coded linker guess, but
  it is accepted or rejected by whether the bytes read like a vector table — never by
  whether the address looks familiar.
- **Windows are vendor-specific.** The initial SP must land in a real RAM alias window
  (`SP_WINDOWS`). The old "0x10000000–0x4FFFFFFF" band admitted the entire peripheral
  space, so a `.rodata` word like `0x3958_4A1D` passed as a stack pointer and the scanner
  found tables in noise.
- **Budget by default.** A 512 KB decode cap keeps a scan at ~1 s; `--full` is there when
  you want every byte and the report prints the coverage either way.
- **A dump is not a proof.** `--base` pins what inference guessed, and the guessed note
  lists every origin that also produced a table, so the reader sees the competition.

## Limitations, honestly

- Cortex-M only (ARM Thumb-2). No AVR, no MIPS, no RTOS symbol recovery.
- It names a *memory map*, not a market part number: `stm32f427xx`, not `STM32F427VGT6`.
  Confirm with DBGMCU/IDCODE, option bytes or the vector-table entry count.
- Identification strength depends on how much device-shaped evidence the image carries.
  A heavily stripped, encrypted or compressed blob yields a container note and a refusal,
  not a chip name.
- DfuSe and OTA/compressed wrappers are detected and **refused**, never guessed. Wrong
  element offsets produce a confidently wrong report, which is worse than no report.
- Register names resolve only where CMSIS gives the block a struct; an offset inside a
  struct hole reports as the block base rather than an invented register.
- The instruction sweep is flow-insensitive and resets at function boundaries: bases held
  across a branch are counted as unknown, not guessed.

## Dual use

Firmware identification is how defenders triage a supply-chain find and how researchers
check what a device they own actually contains. It is also the first step of an attack.
firmprint's answer is to keep the tool on the analysis side of that line: read-only, no
network, no exploit primitives, no flashing, no credential handling, no dumping of a
device — it takes bytes you already legally have and tells you what they are, with the
evidence attached so a reviewer can check it.

Read [SECURITY.md](SECURITY.md) for the reporting policy and the scope statement, and
[docs/case-openmv2.md](docs/case-openmv2.md) / [docs/case-openmv3.md](docs/case-openmv3.md)
for the two worked analyses.

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q          # 287 tests; the sample-dependent ones skip cleanly
python -m ruff check src tools tests
firmprint mcp --self-test
python tools/check_doc_quotes.py   # every report line *and every number in a sentence*
                                   # quoted in this README and docs/case-*.md must be what
                                   # the tool prints today, against live scans
```

Tests are structured around falsifiability, not coverage: several exist specifically to
pin *bugs that were found on the real sample* (peripheral space passing as RAM, vector
tables nested inside each other's entries, block-name counting, a base inferred from a
guessed linker address). Python 3.10–3.12, Linux/macOS/Windows, capstone present and
absent. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Third-party firmware images used for verification are fetched on demand, pinned by
sha256, and never committed to this repository.
