# Security

## What this tool is

`firmprint` reads a firmware image you already have and reports what chip it appears to
be, where it runs from, and which peripherals its code references.  It is analysis
software: it does not write to a device, does not flash, does not dump, does not
exploit, and does not phone anywhere.

The relevant threat model for a tool like this is **the input file**, because a firmware
image is untrusted data and people point analysis tools at samples from strangers.

- **Required install is pure Python standard library.**  There is no C extension in the
  core path, so a malformed ELF cannot reach a `memcpy` — the worst realistic case is a
  Python exception, and the parsers are written to raise a `ContainerError` with a
  message instead.
- **capstone is optional.**  Enabling it (`pip install "firmprint[capstone]"`) pulls in
  a native disassembler, which is where memory-safety bugs live in this class of tool.
  If you cannot audit third-party native code, run `--no-code`: the stdlib path still
  ranks SoC candidates, finds vector tables, and carves constants.  The report labels
  every finding with the engine that produced it, so a `capstone/5.0.7` row and a
  `carve/1` row are never confused.
- **Bounded work by default.**  The instruction sweep runs under a byte budget rather
  than "decode the whole file", because a 200 MB blob is a cheap way to make an analysis
  tool unusable at 3 a.m.  `--full` is opt-in and prints the budget it overrode.
- **No network at analysis time, ever.**  The only outbound connections in the
  repository are in `tools/get_sample.py` and `tools/gen_socdb.py`, both of which fetch
  from a hardcoded HTTPS host, pin an expected sha256, and refuse on mismatch.
  Neither runs during `scan`.
- **The answer key is fetched from an immutable tag.**  `tools/get_sample.py` downloads one
  release asset (`v5.0.1`), checks the archive against a pinned sha256 *before* unpacking,
  then checks every file it writes against its own pin, and exits non-zero instead of
  substituting.  That is a security property, not a convenience: this repository's whole
  claim is that its verification numbers are reproducible, and a build artifact republished
  under a moving name is a supply chain that silently replaces the evidence.  It used to read
  OpenMV's rolling `development` asset and print a note when the digest differed; on
  2026-10-18 the asset moved, CI scanned different bytes than the documents describe, and the
  failure looked like stale documentation.
- **Nothing is written except the report you asked for.**  `--json` and `--md` take an
  explicit path; there is no cache directory, no telemetry, no crash reporter.

## What is deliberately *not* a security feature

The evidence contract (`src/firmprint/evidence.py`) is a correctness guard, not a
sandbox: it refuses to print a confident claim that has no anchored evidence, and
`--strict` makes that a non-zero exit.  It exists because *wrong answers about a chip*
are this tool's real failure mode — a mis-attributed peripheral sends someone reading
the wrong datasheet for three days.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on the repository (Security → Report a
vulnerability), or email the maintainer address on your GitHub profile if private
reporting is unavailable.  Please do not open a public issue for an unfixed
vulnerability.

What is useful in a report: the exact command line, the Python version and OS, whether
capstone was installed, and a reproducer file (or its sha256 if you cannot share it).
For a crash in the native path, the file plus `--no-code` behaviour tells us immediately
whether the bug is in us or in capstone.

Expected first response within 5 working days; a fix or a stated position within 30.
If the bug is in capstone or in a CMSIS header, we will say so and link the upstream
report rather than quietly absorbing it.

## Scope: what this tool is for, and what it is not

Firmware identification is dual-use in the most literal sense: it is how a defender
triages a supply-chain find and how a researcher checks what a device they own actually
contains, and it is also the first step of an attack on a device someone else owns.
The design keeps firmprint on the analysis side of that line, in ways you can check
rather than take on faith:

- it takes bytes you already legally have.  There is no code path that talks to a
  debug probe, a UART bootloader, DFU, or any transport — a JTAG/SWD programmer is the
  tool for getting bytes off a board, and this is not it;
- it never helps you *reach* a device: no credentials handling, no key material, no
  exploit primitives, no protocol clients;
- it produces no executable artefacts: no patched image, no reflashable blob, no
  signed payload.  Findings are offsets, addresses, names, and quoted bytes.

Compressed, encrypted, or wrapper-format images (DfuSe, OTA blobs) are **detected and
refused** rather than guessed: a report built on a wrong container offset is worse than
no report, and "we do not know what this is" is an answer this tool is allowed to give.

This is a statement of design intent, not legal advice.  Analysing firmware you do not
have the right to analyse — or using any identification result against a system without
its owner's permission — is your responsibility, and in most jurisdictions it is also a
crime.

## Supported versions

| version | status |
|---|---|
| 0.1.x | current, supported |
| < 0.1 | unsupported; upgrade first |

Python 3.10, 3.11 and 3.12 are tested on Linux, macOS and Windows, with and without
capstone installed (`.github/workflows/ci.yml`).
