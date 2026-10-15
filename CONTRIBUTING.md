# Contributing

Short version: this project's product is *trustworthy output*, so a change is measured by
whether the report becomes more checkable, not whether it becomes more confident.

## Setup

```bash
git clone https://github.com/xuange-hu/firmprint && cd firmprint
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"                              # pytest + ruff + capstone
python -m pytest -q                                  # sample-dependent tests skip cleanly
python -m ruff check src tools tests
```

Tests run without the firmware samples.  To get them (MIT-licensed OpenMV builds,
pinned by sha256, ~10 MB):

```bash
python tools/get_sample.py --all
```

`samples/` is gitignored.  **Never commit a firmware image** — not even a stripped one.
Binary blobs in this repository would also make the verification claims unverifiable,
because a reader cannot tell whether the file they checked against is the file the numbers
came from.

## The two rules that gate most changes

**1. A finding without anchored evidence does not exist.**  `src/firmprint/evidence.py`
defines the contract: a claim above `STRICT_CONFIDENCE` must carry at least one evidence
item with a `file_offset` or a `vaddr`, and `validate()` reports violations.  The CLI
prints them, and `--strict` turns them into a non-zero exit.  If your change produces a
confident sentence whose bytes you cannot point at, the fix is to lower the confidence or
say what is unknown — not to attach a nearby-but-unrelated offset.

**2. Every finding names the engine that produced it.**  `carve/1` proves a constant is
present; `capstone/5.0.7` proves an instruction reached an address; `vectors/1` reads
table shape; `container/1` parsed a file format.  Do not let one engine's output be
presented as another's, and do not merge two engines' findings into a single row.  The
distinction is the reason a reader can weigh a `peripheral.access` against a
`peripheral.usage`.

The version in a `capstone/...` label is the *distribution* version (`importlib.metadata`),
not the library's `__version__` — the two disagree in the wild, the 5.0.9 wheel still
self-reports 5.0.7 — because a reader who wants to re-run the claim needs the number their
package manager recognises.  Pin the *shape* of an engine label in tests, never its number.

**3. A number quoted in prose must be a number the tool prints today.**  `README.md` and
`docs/case-*.md` paste real report rows, and a heuristic fix silently makes one of them
stale.  `python tools/check_doc_quotes.py` re-scans every fetched sample and checks each
quoted row, each wrapped summary tail, and each `` ```json `` fragment against live output
(JSON fragments must be a *subset* of a real finding, so the docs may elide but not invent).
It runs in CI in the `verification` job, and it is the gate to run after any change that
moves a count or a confidence:

```bash
python tools/check_doc_quotes.py          # needs: python tools/get_sample.py --all
python tools/check_doc_quotes.py --list   # show every quote it checked
```

Without `samples/` it prints a note and exits 0 — the dependency-free CI job has nothing to
compare against, and the check is deliberately not a test of prose style.

Multi-line header quotes are compared as *contiguous transcripts*, so a pasted block must
keep every line the CLI printed in order.  A dropped line is stale even when every surviving
line is real — that is how the OpenMV3 case study ended up quoting a container note whose
"origins that also produced tables" list disagreed with the tool by a count and an order.

## Writing tests the way this suite is written

Tests here are falsification devices, not coverage devices.  Most of the interesting ones
exist because a real sample produced a wrong answer, and each says so in its docstring.
When you fix a bug on the sample, write the test that would have failed before the fix,
and put the *reason* in the docstring rather than the mechanism:

```python
def test_the_cortex_m7_itcm_window_counts_as_ram_and_the_m4_one_does_not():
    """An initial SP of 0x0000_4000 is RAM on an F7 and flash on an F4. ..."""
```

Two habits that keep this honest:

- Prefer asserting on `metrics` numbers and on the presence of a caveat string over
  asserting on exact prose.  Prose should read well; a test that pins a sentence makes
  every wording change look like a regression.
- When a test needs a memory map, use the real generated database
  (`load_soc("stm32f427xx")`), not a hand-typed one.  A hand-typed fixture is how a tool
  ends up passing its own tests and failing on a real image.

Synthetic fixtures belong in `tests/`; anything derived from the samples should say which
real address it came from.

## Adding a chip (the most common contribution)

Memory-map databases are generated from CMSIS headers, not typed:

```bash
python tools/gen_socdb.py fetch --family f4 --device stm32f407xx   # -> socdb-src/
python tools/gen_socdb.py build --family f4 --device stm32f407xx   # -> src/firmprint/data/
firmprint socdb list                  # the new row must show a header sha256
```

The generator records the header's sha256 and byte count into the JSON, so a database can
always be traced back to the file it came from — and a reviewer can diff two versions of a
map by diffing two headers.  Do not edit a generated JSON by hand; if a define is being
dropped, fix the generator and note it in the commit, because `dropped_low_base_defines`
counts exist precisely so that silent losses are visible.

Adding a chip is worth a PR on its own; you do not need to make the ranking smarter at the
same time.

## Verification documents

`verification/*.md` are generated.  If a change moves a number in one of them — recall,
block counts, an inferred base — regenerate rather than editing:

```bash
python tools/make_verification.py            # both boards
```

Every figure in those files is machine-produced, and each document opens with the
evidence-contract violation count for the run it came from — currently **0** for both
boards.  A PR that changes behaviour on a sample should land with the regenerated document
in it, so a reviewer can see the movement instead of taking it on faith.

## Style

Ruff enforces line length 100 (`E501` is off for report prose, which is written to read
well in a terminal), import order, `UP`, `B`, `C4`, `SIM`.  Python 3.10 is the floor —
no `match` statements that need newer syntax, no 3.11-only stdlib.  The core must stay
dependency-free: `dependencies = []` in `pyproject.toml` is a feature, not an oversight
(see SECURITY.md for why).

## Pull requests

Keep them small and say, in the first paragraph, what the report looked like before and
after.  A diff that adds a claim is weaker than a diff that removes a wrong one, and that
is the judgement being applied.

If you are adding a detection, the ideal PR has four things: the code, a test that fails
without it, a regenerated verification document, and one sentence in the report's
`unknowns` about what the new detection still cannot tell you.  That last part is not
decoration — it is the section most readers of this project end up trusting.

## What will not be merged

- Committed firmware images, or any sample fetched at *analysis* time.
- A feature that requires a network call to produce an answer.
- Confidence-raising prose without a matching evidence anchor.
- Unwrapping encrypted/compressed containers by guessing offsets (SECURITY.md explains
  why a wrong offset is worse than a refusal).
