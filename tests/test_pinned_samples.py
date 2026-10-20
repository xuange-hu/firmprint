"""Tests for the fetcher that decides which bytes the answer key describes.

`tools/get_sample.py` looks like plumbing, but it is the step that determines whether
`verification/*.md` is a claim or a story: it used to download a rolling `development`
release, compare the archive digest, and on mismatch print a *note* and carry on.  When that
asset moved in October 2026, CI scanned a build nobody had pinned and the doc gate reported
"the prose is stale" -- a wrong diagnosis of a real failure, which is the kind of bug that
costs an afternoon every time it recurs.

So the fetcher is pinned here the way the heuristics are: it must refuse a build it was not
given digests for, it must not substitute one board's file for another's, and it must only
treat files already on disk as "already fetched" when they verify.

The same file decides what this repository is entitled to *say* about other people's bytes.
It used to call them "MIT-licensed" -- `tools/get_sample.py` said so, and README,
CONTRIBUTING, the CI step name and both generated answer keys repeated it.  Upstream publishes
no root `LICENSE` file, states GPL components, and calls some components proprietary and
non-commercial-only, so the repository was asserting a licence for bytes it had never checked.
`NOTICE.md` is where the honest version lives, and the last tests here keep the prose and that
file agreeing with each other and with the boards actually being fetched.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import pathlib
import re
import sys
import zipfile

import pytest
from conftest import ROOT


def _load(name: str):
    """Checkout-only: a wheel does not ship `tools/`."""
    script = ROOT / "tools" / f"{name}.py"
    if not script.exists():
        pytest.skip("the tool lives in the repository checkout", allow_module_level=True)
    spec = importlib.util.spec_from_file_location(name, script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gs = _load("get_sample")

FW2 = b"\x11" * 64
FW3 = b"\x22" * 64
OTHER = b"\x33" * 8


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def archive(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def board_bytes(fw: bytes) -> dict[str, bytes]:
    """The six files of one board, with `romfs.stamp` left out the way upstream does."""
    return {"firmware.elf": fw, "firmware.bin": fw, "openmv.bin": fw,
            "bootloader.elf": OTHER, "bootloader.bin": OTHER, "romfs0.img": OTHER}


def pins_for(fw: bytes) -> dict[str, str]:
    return {name: digest(fw if name in ("firmware.elf", "firmware.bin", "openmv.bin")
                         else OTHER) for name in gs.WANTED}


@pytest.fixture
def fetch(tmp_path, monkeypatch):
    """A fake two-board bundle, pinned, with `download` replaced and nothing on disk."""
    # ALPHA is in the archive on purpose: a bundle carries every OpenMV target, and the
    # fetcher must not be able to read one board's files for another
    members = {f"{board}/{name}": data
               for board, fw in (("OPENMV2", FW2), ("OPENMV3", FW3), ("ALPHA", OTHER))
               for name, data in board_bytes(fw).items()}
    blob = archive(members)
    dests = {b: tmp_path / "samples" / b.lower() for b in ("OPENMV2", "OPENMV3")}
    monkeypatch.setitem(gs.BOARDS, "OPENMV2", ("OPENMV2", dests["OPENMV2"], pins_for(FW2)))
    monkeypatch.setitem(gs.BOARDS, "OPENMV3", ("OPENMV3", dests["OPENMV3"], pins_for(FW3)))
    monkeypatch.setattr(gs, "ASSET_SHA256", digest(blob))
    calls = []

    def fake_download(url, timeout=900):
        calls.append(url)
        return blob

    monkeypatch.setattr(gs, "download", fake_download)

    def run(*argv: str) -> tuple[int, str, str]:
        buf_out, buf_err = io.StringIO(), io.StringIO()
        monkeypatch.setattr(sys, "argv", ["get_sample.py", *argv])
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            rc = gs.main()
        return rc, buf_out.getvalue(), buf_err.getvalue()

    run.calls = calls
    run.dests = dests
    return run


def test_a_pinned_fetch_writes_both_boards_and_then_verifies(fetch):
    rc, out, _ = fetch("--all")
    assert rc == 0, out
    assert (fetch.dests["OPENMV2"] / "firmware.bin").read_bytes() == FW2
    rc, out, _ = fetch("--all", "--check")
    assert rc == 0, out
    assert "pinned build present" in out


def test_the_second_run_does_not_download_again(fetch):
    fetch("--all")
    before = len(fetch.calls)
    rc, out, _ = fetch("--all")
    assert rc == 0, out
    assert len(fetch.calls) == before, "the digest matched, so the download should be skipped"
    assert "verified by sha256" in out


def test_files_on_disk_are_accepted_only_when_they_verify(fetch):
    """The bug this replaces: `exists()` was the whole test for "already fetched"."""
    fetch("--all")
    (fetch.dests["OPENMV2"] / "firmware.bin").write_bytes(b"some other build")
    rc, out, _ = fetch("--all", "--check")
    assert rc == 1
    assert "NOT the pinned build" in out and "firmware.bin" in out
    calls_before = len(fetch.calls)
    rc, out, _ = fetch("--all")
    assert rc == 0, out
    assert len(fetch.calls) == calls_before + 1, "a stale file must force a refetch"
    assert (fetch.dests["OPENMV2"] / "firmware.bin").read_bytes() == FW2


def test_a_board_directory_is_read_as_a_board_directory(fetch, monkeypatch):
    """`firmware.bin` appears in every board's folder; the prefix is what disambiguates.

    Matching by basename -- the old rule -- would have written whichever folder came first
    in the archive into *both* sample directories, and the answer key would then describe one
    board twice.
    """
    blob = archive({**{f"OPENMV3/{n}": d for n, d in board_bytes(FW3).items()},
                    **{f"OPENMV2/{n}": d for n, d in board_bytes(FW2).items()}})
    monkeypatch.setattr(gs, "ASSET_SHA256", digest(blob))
    monkeypatch.setattr(gs, "download", lambda url, timeout=900: blob)
    rc, out, _ = fetch("--all")
    assert rc == 0, out
    assert (fetch.dests["OPENMV3"] / "firmware.bin").read_bytes() == FW3
    assert (fetch.dests["OPENMV2"] / "firmware.bin").read_bytes() == FW2


def test_an_unpinned_build_is_refused_and_nothing_is_written(fetch, monkeypatch):
    blob = archive({**{f"OPENMV2/{n}": d for n, d in board_bytes(OTHER).items()},
                    **{f"OPENMV3/{n}": d for n, d in board_bytes(FW3).items()}})
    monkeypatch.setattr(gs, "ASSET_SHA256", digest(blob))
    monkeypatch.setattr(gs, "download", lambda url, timeout=900: blob)
    rc, _out, err = fetch("--board", "OPENMV2")
    assert rc == 1
    assert "not the one the answer key describes" in err and "firmware.bin" in err
    assert "Refusing to substitute" in err
    assert not (fetch.dests["OPENMV2"] / "firmware.bin").exists(), \
        "refusing must refuse *before* writing, or the answer key describes bytes it " \
        "only half-fetched"


def test_allow_drift_writes_and_hands_over_the_new_pins(fetch, monkeypatch):
    blob = archive({**{f"OPENMV2/{n}": d for n, d in board_bytes(OTHER).items()},
                    **{f"OPENMV3/{n}": d for n, d in board_bytes(FW3).items()}})
    monkeypatch.setattr(gs, "ASSET_SHA256", digest(blob))
    monkeypatch.setattr(gs, "download", lambda url, timeout=900: blob)
    rc, _out, err = fetch("--board", "OPENMV2", "--allow-drift")
    assert rc == 1, "drift is a real event: it must not look like a clean run"
    assert "DIGESTS MOVED" in err
    assert digest(OTHER) in err, "the paste-ready pin table is the whole point of the flag"
    assert (fetch.dests["OPENMV2"] / "firmware.bin").read_bytes() == OTHER


def test_a_missing_member_is_reported_as_a_layout_change(fetch, monkeypatch):
    blob = archive({"OPENMV2/firmware.elf": FW2, "OPENMV2/firmware.bin": FW2,
                    "OPENMV2/openmv.bin": FW2, "OPENMV2/bootloader.elf": OTHER,
                    "OPENMV2/bootloader.bin": OTHER})
    monkeypatch.setattr(gs, "ASSET_SHA256", digest(blob))
    monkeypatch.setattr(gs, "download", lambda url, timeout=900: blob)
    rc, _out, err = fetch("--board", "OPENMV2")
    assert rc == 2
    assert "layout changed" in err and "romfs0.img" in err


def test_a_check_with_no_pins_cannot_pass(fetch, monkeypatch):
    """A check that compared nothing must not print a pass."""
    monkeypatch.setitem(gs.BOARDS, "OPENMV2", ("OPENMV2", fetch.dests["OPENMV2"], {}))
    rc, _out, err = fetch("--board", "OPENMV2", "--check")
    assert rc == 1
    assert "no pinned digests" in err


def test_an_unpinned_board_is_refused_before_the_download(fetch, monkeypatch):
    """The re-pin path is `--show-pins`; everything else has to stop without a byte in flight.

    This is the state the repository is in right after `RELEASE` is pointed at a new tag: the
    pins are empty.  Without this guard, CI -- or a contributor on a 1.2 MB/min link -- spends
    a long download to arrive at "I cannot verify these files", and the failure looks like a
    network problem.
    """
    monkeypatch.setitem(gs.BOARDS, "OPENMV2", ("OPENMV2", fetch.dests["OPENMV2"], {}))
    rc, _out, err = fetch("--all")
    assert rc == 1
    assert "no pinned digests" in err and "OPENMV2" in err
    assert "Nothing was downloaded" in err
    assert fetch.calls == [], "refusing after transferring 91 MB is not refusing"


def test_show_pins_is_the_one_path_that_fetches_unpinned_bytes(fetch, monkeypatch):
    monkeypatch.setitem(gs.BOARDS, "OPENMV2", ("OPENMV2", fetch.dests["OPENMV2"], {}))
    monkeypatch.setattr(gs, "ASSET_SHA256", "")
    rc, _out, _err = fetch("--all", "--show-pins")
    assert rc == 0, "the flag that establishes pins cannot also be blocked by their absence"
    assert len(fetch.calls) == 1


def test_the_printed_pin_entry_is_python(fetch):
    """`--show-pins` is paste-able or it is decoration."""
    rc, out, _ = fetch("--board", "OPENMV2", "--show-pins")
    assert rc == 0, out
    snippet = out[out.index('"OPENMV2": ('):out.index("\nnext:")].strip().rstrip(",")
    entry = eval("{" + snippet + "}", {"ROOT": pathlib.Path("x")})  # noqa: S307
    _prefix, dest, pins = entry["OPENMV2"]
    assert dest.name == "openmv2"
    assert pins == pins_for(FW2)
    assert len(pins) == len(gs.WANTED)


def test_the_archive_digest_is_enforced_before_unpacking(fetch, monkeypatch):
    monkeypatch.setattr(gs, "ASSET_SHA256", digest(b"the pinned archive"))
    rc, _out, err = fetch("--all")
    assert rc == 1
    assert "is not the pinned build" in err and "A tagged release must not move" in err
    assert not fetch.dests["OPENMV2"].exists()


# ------------------------------------------------------------------------ licence prose

#: The nouns nobody here has a licence to claim.  `code` and `source` are deliberately absent:
#: upstream's own sentence ("most of the code in the repository is licensed under the MIT
#: license") is quoted in `NOTICE.md`, and it is about *source*, which is not what we fetch.
_FIRMWARE = r"openmv|firmware|images?|samples?|boards?|artifacts?|binaries?"

#: "MIT-licensed OpenMV firmware", "MIT licensed samples" -- the adjectival form, which is how
#: this repository actually wrote the claim.
ADJECTIVAL = re.compile(rf"MIT[- ]licensed(?:\W+\w+){{0,3}}?\W*\b({_FIRMWARE})\b", re.I)

#: "... the firmware images are MIT": the predicate form an honest-sounding rewrite reaches for.
#: "images are *not* MIT" does not match, because `is|are` has to sit next to the licence.
PREDICATE = re.compile(rf"\b({_FIRMWARE})\b(?:\W+\w+){{0,3}}\b(?:is|are)\b\W*MIT\b", re.I)

#: "... firmware images licensed under the MIT license".
UNDER = re.compile(rf"\b({_FIRMWARE})\b(?:\W+\w+){{0,4}}licensed\W+(?:under\s+)?(?:the\s+)?MIT\b",
                   re.I)


def _claim_files():
    """Every file a reader reaches that states (or implies) what the samples are licensed under.

    Tests are deliberately not in this list: this very file quotes the false claim it exists to
    prevent, and a lint that cannot distinguish a claim from a quotation of one is a lint people
    turn off.  The prose files are written to be checkable -- `NOTICE.md` refuses in a shape
    these patterns do not match, so a refusal is not an exemption.
    """
    files = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md",
             ROOT / "NOTICE.md", *sorted((ROOT / "docs").glob("*.md")),
             *sorted((ROOT / "verification").glob("*.md")),
             *sorted((ROOT / "tools").glob("*.py")),
             *sorted((ROOT / "src" / "firmprint").glob("*.py")),
             *sorted((ROOT / ".github").rglob("*.yml")),
             *sorted((ROOT / ".github").rglob("*.md"))]
    return [f for f in files if f.exists()]


def mit_claims(text: str) -> list[str]:
    """Lines that assert a licence for someone else's build artifacts."""
    out = []
    for line in text.splitlines():
        for pattern in (ADJECTIVAL, PREDICATE, UNDER):
            if pattern.search(line):
                out.append(line.strip())
                break
    return out


def test_no_prose_claims_a_licence_for_firmware_it_did_not_write():
    """The false statement this repository shipped was "MIT-licensed OpenMV firmware".

    Not a hypothesis: `git show HEAD:README.md` before the correction carried it in the
    verification section, `CONTRIBUTING.md` in the sample-fetching instructions,
    `tools/get_sample.py` in its module docstring, `tools/make_verification.py` twice -- which
    is how it reached both generated answer keys -- and the CI step name.  Upstream's README
    says the opposite in the same breath as the word MIT: *most* of the code, with GPL image
    libraries and proprietary non-commercial-only components, and there is no root `LICENSE`
    file to point at.  A release artifact cannot be licensed by a badge on its repository.

    The rule is aimed at the claim, not the word: `NOTICE.md` and the README's License section
    both say "MIT" about the firmware in order to refuse to license it, and neither matches.
    It is a shape check, so it is not omniscient: a sentence that puts "MIT" and "firmware" in
    adjacent clauses without predication (the old `MIT. Third-party firmware images used for
    verification are fetched...` paragraph) is outside its reach, which is why the README now
    says what it means in the words these patterns can see.
    """
    offenders = {f.relative_to(ROOT).as_posix(): mit_claims(f.read_text(encoding="utf8"))
                 for f in _claim_files()}
    bad = {name: lines for name, lines in offenders.items() if lines}
    assert not bad, "prose licenses bytes it did not write: " + "; ".join(
        f"{name}: {line}" for name, lines in sorted(bad.items()) for line in lines)


def test_the_denial_is_still_written_where_the_claim_used_to_be():
    """Removing a false claim silently is one edit; removing the *reason* is invisible.

    `NOTICE.md` only earns its place if it keeps both halves: upstream's words quoted rather
    than paraphrased, and what we checked and could not establish.  Either half going missing
    turns the file into a disclaimer, which is the shape of sentence this repository has to be
    most careful about trusting.
    """
    notice = ROOT / "NOTICE.md"
    assert notice.exists(), "NOTICE.md is gone: the licence story has no home"
    text = notice.read_text(encoding="utf8")
    # upstream, quoted: the GPL exception and the proprietary exception, in its words
    quoted = [line[2:].strip() for line in text.splitlines() if line.startswith("> ")]
    joined = " ".join(quoted)
    assert "MIT license" in joined, "the quote no longer contains upstream's MIT sentence"
    assert "licensed under the GPL" in joined and "non-commercial use only" in joined, \
        "the quote no longer contains the two exceptions that made the plain MIT claim wrong"
    assert re.search(r"[0-9a-f]{40}", text), \
        "the quote is unattributable: no commit it was read at"
    # and our own refusal, with the check behind it
    assert re.search(r"does \*\*not\*\* describe these firmware images as .MIT.", text), \
        "NOTICE.md no longer says outright that it will not call these images MIT"
    assert "no `LICENSE` file" in text or "not Found" in text, \
        "NOTICE.md no longer records what it looked for and did not find"


def test_notice_describes_the_boards_that_are_actually_being_fetched():
    """The gate for adding a board, so it cannot be skipped by forgetting it exists.

    `NOTICE.md` ends with a rule for the next sample batch -- record the directory, the real
    part, the digests, and what you checked about its licence.  Prose cannot enforce a rule, so
    this does: every board in `BOARDS` has to be named in the notice, and the release and
    archive digest the fetcher pins have to be the ones the notice publishes.  Re-pin
    `RELEASE` or `ASSET_SHA256` alone, or add a `PORTENTA_H7` board alone, and this fails
    before an answer key describes bytes nobody accounted for.
    """
    text = (ROOT / "NOTICE.md").read_text(encoding="utf8")
    for board, (_prefix, _dest, pins) in sorted(gs.BOARDS.items()):
        assert board in text, f"{board} is fetched but not described in NOTICE.md"
        assert pins, f"{board} has no pins: NOTICE.md cannot be accounting for its files"
    assert gs.RELEASE in text and gs.ASSET_SHA256 in text, \
        "NOTICE.md and the fetcher stopped naming the same build"
    assert f"{gs.RELEASE}.zip" in text or "firmware_" in text, \
        "NOTICE.md does not name the asset the digest belongs to"
    assert "## Adding a board" in text, \
        "the notice stopped telling the next contributor what to record about a new sample"
    # the README and the contributor guide have to lead a reader here
    for f in (ROOT / "README.md", ROOT / "CONTRIBUTING.md"):
        assert "NOTICE.md" in f.read_text(encoding="utf8"), f"{f.name} hides the notice"
    # a wheel is the only artifact that ships without a checkout, so the notice goes in it
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf8")
    license_files = re.search(r"^license-files\s*=\s*\[[^\]]*\]", pyproject, re.M)
    assert license_files and "NOTICE.md" in license_files.group(0), \
        "the wheel ships LICENSE and nothing else: an installer reads 'MIT' and never learns " \
        "that the verification images are somebody else's build artifacts"
