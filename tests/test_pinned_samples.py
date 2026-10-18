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
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import pathlib
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
