"""The command line: what a stranger types, and what comes back.

These tests drive `main()` directly (no subprocess, no installed console script)
and care about three things a reviewer will hit on day one: the output is
parseable, a failure is a one-line message rather than a traceback, and the
strict flag means what it says.
"""
from __future__ import annotations

import json
import re

import pytest
from conftest import cortex_m_image

from firmprint import cli

# ------------------------------------------------------------------------------ scan

def test_json_format_prints_a_parseable_report(elf_path, capsys):
    assert cli.main(["scan", str(elf_path), "--format", "json", "--no-code"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "firmprint-report/1"
    assert report["meta"]["engines"]["decode"] is None


def test_text_output_is_a_table_not_a_blob(elf_path, capsys):
    assert cli.main(["scan", str(elf_path), "--no-code"]) == 0
    out = capsys.readouterr().out
    assert f"{'kind':<24}{'subject':<20}{'conf':>5}  summary" in out
    assert "contract    0 violation(s)" in out
    assert "DO NOT TRUST" not in out
    assert out.startswith("file        firmware.elf")


def test_the_markdown_format_writes_the_same_report(elf_path, capsys):
    assert cli.main(["scan", str(elf_path), "--format", "md", "--no-code"]) == 0
    md = capsys.readouterr().out
    assert md.startswith("# firmprint report")
    assert "| finding | subject | conf | summary |" in md


def test_json_and_md_files_are_written_when_asked(elf_path, tmp_path, capsys):
    rep, md = tmp_path / "r.json", tmp_path / "r.md"
    rc = cli.main(["scan", str(elf_path), "--no-code", "--json", str(rep), "--md", str(md)])
    assert rc == 0
    assert "wrote" in capsys.readouterr().out
    assert json.loads(rep.read_text(encoding="utf8"))["findings"]
    assert md.read_text(encoding="utf8").startswith("# firmprint report")


def test_max_findings_says_what_it_hid(elf_path, capsys):
    cli.main(["scan", str(elf_path), "--no-code", "--max-findings", "3"])
    out = capsys.readouterr().out
    assert "more finding(s): use --max-findings or --json" in out


def test_the_candidate_line_is_sorted_by_what_the_maps_explain(elf_path, capsys):
    cli.main(["scan", str(elf_path), "--no-code"])
    line = next(ln for ln in capsys.readouterr().out.splitlines()
                if ln.startswith("candidates"))
    # "<name>=<distinct device constants> constants/<blocks> blocks", best first: the
    # number a reader should compare is the one the ranking is built on
    rows = re.findall(r"(\S+?)=(\d+) constants/(\d+) blocks", line)
    assert [int(n) for _n, n, _b in rows] == sorted((int(n) for _n, n, _b in rows), reverse=True)
    assert len(rows) == 3, line
    assert "constants/" in line and "blocks" in line


def test_a_pinned_base_and_hex_budget_are_accepted(bin_path, capsys):
    assert cli.main(["scan", str(bin_path), "--base", "0x08000000", "--budget", "0x1000"]) == 0
    out = capsys.readouterr().out
    assert "decoded     " in out


def test_soc_overrides_the_ranking_instead_of_asking_for_it(bin_path, capsys):
    """`--soc` is the "I know what board this is" switch: the report must say that part.

    The F7 database is the wrong one for an F4 build, which is exactly why this test
    pins it: if the ranking quietly won, `--soc` would be decoration.
    """
    assert cli.main(["scan", str(bin_path), "--soc", "stm32h743xx", "--no-code",
                     "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["meta"]["soc"]["device"] == "stm32h743xx"
    assert report["meta"]["soc_scan"]["databases_considered"] == ["stm32h743xx"]


def test_full_ignores_the_budget_it_was_given(bin_path, capsys):
    from firmprint.decode import available as capstone_available
    if not capstone_available():
        pytest.skip("capstone not installed: nothing to compare")
    assert cli.main(["scan", str(bin_path), "--budget", "4096", "--format", "json"]) == 0
    capped = json.loads(capsys.readouterr().out)
    assert cli.main(["scan", str(bin_path), "--full", "--format", "json"]) == 0
    whole = json.loads(capsys.readouterr().out)
    assert capped["meta"]["decode"]["bytes_decoded"] <= 4096
    assert whole["meta"]["decode"]["bytes_decoded"] > capped["meta"]["decode"]["bytes_decoded"]
    assert whole["meta"]["decode"]["coverage"] > capped["meta"]["decode"]["coverage"]


# --------------------------------------------------------------------------- failures

def test_a_missing_file_is_a_message_not_a_traceback(tmp_path, capsys):
    assert cli.main(["scan", str(tmp_path / "nope.bin")]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and "Traceback" not in err


def test_an_unwrapped_ota_container_is_refused_with_an_instruction(tmp_path, capsys):
    p = tmp_path / "ota.bin"
    p.write_bytes(b"\x1f\x8b\x08\x00" + bytes(300))
    assert cli.main(["scan", str(p)]) == 2
    assert "decompress first" in capsys.readouterr().err


def test_strict_turns_a_contract_violation_into_a_failing_exit(monkeypatch, capsys):
    bad = {"schema": cli.SCHEMA, "meta": _stub_meta(), "contract": {"strict": True,
                                                                    "violations": ["x: no evidence"]},
           "findings": []}
    monkeypatch.setattr(cli, "analyze", lambda *a, **k: bad)
    assert cli.main(["scan", "whatever.bin"]) == 0            # tells you, still exits clean
    out = capsys.readouterr().out
    assert "VIOLATION   x: no evidence" in out and "DO NOT TRUST THIS REPORT" in out
    assert cli.main(["scan", "whatever.bin", "--strict"]) == 1


def test_a_dump_of_erasable_size_still_produces_a_report(tmp_path, capsys):
    p = tmp_path / "tiny.bin"
    p.write_bytes(cortex_m_image(code_bytes=0x400))
    assert cli.main(["scan", str(p), "--no-code"]) == 0
    assert "contract    0 violation(s)" in capsys.readouterr().out


# ---------------------------------------------------------------------------- socdb

def test_socdb_list_names_every_installed_database(capsys):
    assert cli.main(["socdb", "list"]) == 0
    out = capsys.readouterr().out
    assert "stm32f427xx" in out and "stm32h743xx" in out
    assert "blocks" in out and "structs" in out


def test_socdb_show_prints_a_summary_and_the_first_blocks(capsys):
    assert cli.main(["socdb", "show", "stm32f427xx", "--limit", "200"]) == 0
    out = capsys.readouterr().out
    summary, end = json.JSONDecoder().raw_decode(out)     # JSON first, then the block list
    # the core label comes from the CMSIS header's own __CM4_REV define, not from a
    # family-string guess, so it must read as a real core name
    assert summary["device"] == "stm32f427xx" and summary["core"] == "cortex-m4"
    rest = out[end:]
    assert "  GPIOA" in rest and "0x40020000" in rest


def test_the_match_line_shows_confidence_and_the_database_it_came_from(elf_path, capsys):
    """A part name on its own reads like a fact; the line must say how sure it is.

    `match` therefore carries the confidence, the verdict word the ranking chose
    ("best match" vs "no installed map is distinctive here") and the header hash
    the map was built from, so a reader can tell a 0.9 identification from a 0.5 guess.
    """
    cli.main(["scan", str(elf_path), "--no-code"])
    lines = capsys.readouterr().out.splitlines()
    match = next(ln for ln in lines if ln.startswith("match"))
    assert "conf 0." in match and "stm32f427xx" in match
    assert any(ln.startswith("            db ") and "cmsis-device-f4" in ln for ln in lines)


def test_socdb_show_without_a_name_is_a_usage_error(capsys):
    assert cli.main(["socdb", "show"]) == 2
    assert "usage: firmprint socdb show <device>" in capsys.readouterr().err


def test_socdb_on_an_empty_data_dir_says_so(tmp_path, capsys):
    assert cli.main(["socdb", "list", "--data-dir", str(tmp_path)]) == 1
    assert "no databases" in capsys.readouterr().out


def test_an_unknown_socdb_verb_is_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["socdb", "diff"])
    assert exc.value.code == 2


def test_version_is_reported_with_the_schema(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert f"firmprint {cli.__version__}".split()[0] == "firmprint"
    assert "firmprint-report/1" in out


# --------------------------------------------------------------------------- verify

def test_verify_scores_the_sample_against_its_own_symbols(elf_path, tmp_path, capsys):
    out = tmp_path / "v.json"
    assert cli.main(["verify", str(elf_path), "--json", str(out)]) == 0
    text = capsys.readouterr().out
    assert "confirmed 14/14" in text
    assert "contract: 0 violation(s)" in text
    payload = json.loads(out.read_text(encoding="utf8"))
    assert payload["verify"]["missed"] == []
    assert payload["verify"]["recall_over_drivers"] == 1.0


def test_verify_says_plainly_when_an_image_has_no_symbols(tmp_path, capsys):
    p = tmp_path / "bare.bin"
    p.write_bytes(cortex_m_image(code_bytes=0x400))
    assert cli.main(["verify", str(p)]) == 0
    assert "no oracle available" in capsys.readouterr().out


def test_verify_pins_a_base_for_a_dump_from_the_command_line(bin_path, capsys):
    """`verify --base` has to be wired through argparse, not only through the library."""
    assert cli.main(["verify", str(bin_path), "--base", "0x08000000"]) == 0
    assert "matched part" in capsys.readouterr().out


def test_verify_strict_reaches_the_command_from_the_command_line(monkeypatch, tmp_path):
    from firmprint import verify
    got: dict = {}
    report = {"meta": {"file": {"path": "x.elf", "size": 1, "sha256": "0" * 64},
                       "container": {}, "soc": None, "decode": {}, "carve_stats": {}},
              "findings": [], "contract": {"strict": True, "violations": ["x: no evidence"]}}
    result = {"rows": [], "detected_peripherals": 0, "oracle_modules": 0, "confirmed": 0,
              "missed": [], "recall_over_drivers": 0.0, "unconfirmed_peripherals": [],
              "peripherals_by_engine": {}}

    def fake(path, **kw):
        got.update(kw)
        return report, result, {}

    monkeypatch.setattr(verify, "run_verification", fake)
    p = tmp_path / "x.elf"
    assert cli.main(["verify", str(p), "--base", "0x08001000", "--soc", "stm32f427xx"]) == 0
    assert got["base"] == 0x08001000 and got["soc"] == "stm32f427xx"
    assert cli.main(["verify", str(p), "--strict"]) == 1


def _stub_meta() -> dict:
    return {"file": {"path": "whatever.bin", "size": 1, "sha256": "0" * 64},
            "container": {"format": "raw", "arch": "arm", "segments": [], "entry": None},
            "soc": {"device": "stm32f427xx", "family": "f4", "core": "cortex-m4",
                    "peripherals": 1, "provenance": {"source_repo": "x", "header_sha256": "y"}},
            "soc_scan": {"databases_considered": ["stm32f427xx"],
                         "per_database": {"stm32f427xx": {"blocks": 1, "device_constants": 1}}},
            "engines": {"carve": "carve/1"}, "decode": {"engine": None, "reason": "requested"},
            "carve_stats": {}}
