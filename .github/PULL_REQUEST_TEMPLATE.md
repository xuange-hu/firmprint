## What does the report say differently after this?

One paragraph. If the change cannot be described as "a claim that used to be
`X 0.66` is now `Y 0.76`, because…", it is probably a refactor, and a refactor PR should
say so out loud.

## Evidence

- [ ] `python -m pytest -q` passes (and the new/changed behaviour has a test that
      **would have failed before the fix** — say which one it is)
- [ ] `python -m ruff check src tools tests` clean
- [ ] `firmprint mcp --self-test` ok, if anything under `mcp_server.py` moved
- [ ] `python tools/get_sample.py --all && python tools/check_doc_quotes.py` ok, if any
      count, confidence or summary line changed — the README and `docs/case-*.md` quote
      real output and go stale silently
- [ ] `python tools/make_verification.py` produces no diff (beyond the `runtimes:` line) —
      otherwise commit the regenerated `verification/*.md` in this PR
- [ ] `firmprint scan samples/*/firmware.bin --strict` still exits 0 on all four raw dumps

## If this touches a heuristic

Name the falsifying case: what image, or what byte pattern, would make the new rule wrong,
and what does the tool do then? A rule that cannot be wrong cannot be checked either.

If it fixes a bug found on a real sample, the commit message should contain the address
where the old code went wrong — that is what turns the fix into documentation.

## If this adds a SoC map

Attach the generated JSON only, never the header, never firmware. Confirm `firmprint socdb
list` shows the new row with a header sha256, and say whether the map *separates* anything
from the already-installed maps (`exclusive_constants` on a sample is the honest answer if
you have one).

## If nothing here applies

Say what you checked instead, rather than leaving the boxes empty. An unchecked box with no
note reads as "the CI will tell you", and CI does not tell you about a confident sentence
whose bytes were never pointed at.
