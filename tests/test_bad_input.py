"""Inputs that carry no evidence must not leave with an answer that looks like one.

These are the cases where a confident-looking report is *unreachable by construction*: a
file that stops halfway through an ELF header, a one-byte dump, an installed box with no
memory-map database.  Each test is written against the sentence the tool is allowed to say,
because the failure mode this project cannot afford is not a crash -- it is a clean-looking
row that nobody earned.
"""
from __future__ import annotations

import struct

import pytest
from conftest import cortex_m_image

from firmprint import analyze, cli


def write(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_a_file_that_stops_in_the_identification_bytes_is_a_usage_error(tmp_path, capsys):
    """`\\x7fELF` alone used to raise IndexError from `raw[4]`, which the CLI does not catch.

    The traceback was the whole bug class: `struct.error` and `IndexError` are not
    `ValueError`, so the usage-error handler let them through as stack traces.
    """
    rc = cli.main(["scan", str(write(tmp_path, "tiny.elf", b"\x7fELF")), "--no-code"])
    err = capsys.readouterr().err
    assert rc == 2, err
    assert "truncated ELF" in err and "Traceback" not in err


@pytest.mark.parametrize("size", [21, 40, 51])
def test_a_header_too_short_for_the_fields_we_read_says_which(tmp_path, capsys, size):
    """ELF32 needs 52 bytes for the fields `load_elf` touches; report the shortfall."""
    head = b"\x7fELF\x01\x01\x01\x00" + struct.pack("<HHI", 2, 40, 0x54) + bytes(size - 16)
    rc = cli.main(["scan", str(write(tmp_path, "short.elf", head)), "--no-code"])
    err = capsys.readouterr().err
    assert rc == 2 and "truncated ELF32 header" in err, err
    assert f"need {52}" in err.replace("needs 52", "need 52")


def test_a_one_byte_file_identifies_nothing(tmp_path):
    """It used to come back as `stm32f427xx, conf 0.35`.

    A map that explains no device constant, and does not contain the load region or the
    reset stack pointer, has contributed nothing; ranking it as a candidate puts a part
    name on zero evidence.
    """
    report = analyze(str(write(tmp_path, "one.bin", b"\x00")), skip_code=True)
    assert [f["subject"] for f in report["findings"] if f["kind"] == "soc.candidate"] == []
    assert report["meta"]["soc"] is None


def test_an_image_where_nothing_scored_does_not_describe_a_reasoned_guess(tmp_path, capsys):
    """The note must not read like the one printed when a table *was* found.

    Both forms start from `guess_load_base()` returning zero, so the old text said
    "inferred as 0x00000000: of the 12 origins tested it is the one whose best candidate
    reads most like a vector table (0 table(s) there)" -- a null result dressed as a
    choice, in the same shape as the real one.
    """
    cli.main(["scan", str(write(tmp_path, "zero.bin", b"")), "--no-code"])
    out = capsys.readouterr().out
    assert "no vector table at any of the 12 origins tested" in out
    assert "reads most like a vector table" not in out
    assert "carries no evidence" in out


def test_a_base_that_was_actually_found_still_uses_the_reasoned_sentence(tmp_path, capsys):
    """The other half of the pin: the honest version must not swallow the real case."""
    blob = write(tmp_path, "ok.bin", cortex_m_image())
    cli.main(["scan", str(blob), "--no-code"])
    out = capsys.readouterr().out
    assert "load base inferred as 0x08000000" in out
    assert "reads most like a vector table" in out


def test_no_installed_databases_is_a_value_error_not_a_system_exit(tmp_path):
    """`SystemExit` slips past `except Exception`, so the MCP session died with it.

    The message is pinned too: it used to tell the reader to run `firmprint socdb add`,
    which is not a command.
    """
    empty = tmp_path / "db"
    empty.mkdir()
    with pytest.raises(ValueError) as excinfo:
        analyze(str(write(tmp_path, "img.bin", cortex_m_image())), data_dir=empty,
                skip_code=True)
    message = str(excinfo.value)
    assert not isinstance(excinfo.value, SystemExit)
    assert "socdb add" not in message
    assert "firmprint build" in message and "socdb list" in message


def test_a_truncated_table_row_shows_that_it_was_cut():
    """`0 high-entropy bloc` is indistinguishable from a label the tool actually uses."""
    assert cli._clip("0 high-entropy block", 20) == "0 high-entropy block"
    assert cli._clip("0 high-entropy block", 19) == "0 high-entropy blo…"
    assert len(cli._clip("0 high-entropy block", 19)) == 19      # the ellipsis is inside
    assert len(cli._clip("x" * 400, 96)) == 96
