"""Tests for the shape of the workflow files, because a broken CI config fails silently.

`.github/workflows/ci.yml` is the document that says what this repository guarantees.  When
its syntax is wrong, GitHub does not report a failing step: it starts no jobs at all, the run
goes *completed / failure* in the same second it was created, and the only visible difference
from a green run is the absence of everything.  That is not a hypothetical -- on 2026-10-20 a
step name written as

    - name: Fetch pinned third-party samples (licence provenance: NOTICE.md)

bought exactly that.  In YAML a plain (unquoted) scalar may not contain ": ", because the pair
of characters means "this line is a mapping"; the parser sees a second key inside a scalar,
rejects the file, and no job -- including the one that runs `pytest` -- ever starts.

So the rule is checked here with no dependency (the package installs nothing, and PyYAML would
have to be pip-installed on an incident machine to notice a typo).  The limitation is stated
plainly rather than glossed: **this test cannot rescue a push that already broke the
workflow**, because the workflow is what runs it.  It is for `python -m pytest -q` before
pushing, which is why CONTRIBUTING.md lists it as the step that has to pass locally.
"""
from __future__ import annotations

import re

from conftest import ROOT

#: `key:` or `- key:` followed by the value, at any indent.  Only used to find the *start* of
#: a scalar; the block-scalar bookkeeping below decides which lines are values at all.
_KEY = re.compile(r"^(?P<indent>\s*)-?\s*(?P<key>[\w.-]+)\s*:\s*(?P<val>.*)$")

#: a value opening one of these is not a plain scalar: block scalar, flow collection, quoted
#: string, anchor/alias, or a key that just introduces a nested mapping (empty value).
_NOT_PLAIN = ("|", ">", "[", "{", "'", '"', "&", "*", "?")


def plain_scalar_problems(text: str) -> list[str]:
    """Lines whose YAML value is a plain scalar containing `": "` -- a parse error, every time."""
    problems: list[str] = []
    lines = text.splitlines()
    block_indent: int | None = None  # set while inside a `run: |` body, whose lines are not YAML
    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if block_indent is not None:
            if not stripped or indent > block_indent:
                continue  # body line, or a blank that belongs to the body
            block_indent = None
        if not stripped or stripped.startswith("#"):
            continue
        m = _KEY.match(raw)
        if not m:
            continue
        val = m.group("val").strip()
        # a trailing `  # comment` is not part of the scalar, so it cannot break it
        val = re.split(r"\s+#", val, maxsplit=1)[0].rstrip()
        if val.startswith(_NOT_PLAIN):
            if val[0] in "|>":
                block_indent = indent
            continue
        if not val:
            continue
        if ": " in val:
            problems.append(f"line {number}: {stripped[:88]}")
        elif val.endswith(":"):
            problems.append(f"line {number}: value ends on a colon: {stripped[:88]}")
    return problems


def test_the_workflows_are_parseable_yaml_in_the_way_github_reads_them():
    """The whole file, every job, every step name.

    `run: |` bodies legitimately contain `echo "::error::..."` and `python -c "...assert
    set(l)>={'LICENSE','NOTICE.md'},l..."`, which is exactly the text a naive line scanner
    would flag -- so this doubles as the proof that the block-scalar bookkeeping works: if it
    did not, the clean file would report violations.
    """
    files = sorted((ROOT / ".github").rglob("*.yml")) + sorted((ROOT / ".github").rglob("*.yaml"))
    assert files, "no workflow files found: the check became nothing"
    bad = {f.relative_to(ROOT).as_posix(): plain_scalar_problems(f.read_text(encoding="utf8"))
           for f in files}
    bad = {name: lines for name, lines in bad.items() if lines}
    assert not bad, "GitHub would refuse to start a single job: " + "; ".join(
        f"{name} -> {line}" for name, lines in sorted(bad.items()) for line in lines)


def test_the_shape_that_broke_ci_on_2026_10_20_is_caught():
    """The falsifying case, verbatim: a step name whose parentheses hold a colon.

    Rewriting it as `'Fetch ... (licence provenance: NOTICE.md)'` is the fix that went in, and
    the quoted form is asserted to stay clean -- a lint that punishes the cure is a lint that
    gets deleted.
    """
    broken = ("jobs:\n  w:\n    steps:\n"
              "      - name: Fetch pinned third-party samples (licence provenance: NOTICE.md)\n"
              "        run: python tools/get_sample.py --all\n")
    p = plain_scalar_problems(broken)
    assert len(p) == 1 and "licence provenance" in p[0], p
    fixed = broken.replace("- name: Fetch", "- name: 'Fetch").replace(
        "NOTICE.md)", "NOTICE.md)'")
    assert plain_scalar_problems(fixed) == [], fixed
    # and the same trap in a value people write on one line
    assert plain_scalar_problems("  run: echo note: mind the colon\n")
    assert plain_scalar_problems('  run: "echo note: mind the colon"\n') == []


def test_a_block_scalar_body_is_not_read_as_yaml():
    """`run: |` content is shell, and the shell in this file contains colons on purpose.

    Without this, the check would fire on `echo "::error::verification/*.md changed -- commit
    the regenerated documents"` -- a line the repository has had for weeks -- and the first
    contributor to see a false failure would start ignoring the failure.
    """
    text = ("      - name: Diff the answer keys\n"
            "        run: |\n"
            '          echo "::error::verification/*.md changed -- commit them"\n'
            '          python -c "import json;d={\'a\': 1};print(d)"\n'
            "          test -n x\n"
            "      - name: Next step\n"
            "        run: python tools/get_sample.py --all\n")
    assert plain_scalar_problems(text) == []
    # the structure after the body still gets checked: a bad step name below a block scalar
    # must not be swallowed by the skip
    assert plain_scalar_problems(text.replace(
        "      - name: Next step", "      - name: Next step (licence: NOTICE)"))
