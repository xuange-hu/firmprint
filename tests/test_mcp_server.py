"""The stdio MCP server: protocol shape, error codes, and what a tool actually returns.

An agent will trust this server's output, so the tests pin the parts that make a
claim checkable: the report schema id travels in `initialize`, errors are JSON-RPC
errors rather than text that looks like a result, and a scan reply still carries
`contract.violations` so the caller can refuse an untrustworthy report.
"""
from __future__ import annotations

import io
import json
import struct

import pytest
from conftest import cortex_m_image

from firmprint import mcp_server as mcp


def call(method, params=None, rid=1) -> dict:
    return mcp.dispatch({"jsonrpc": "2.0", "id": rid, "method": method,
                         "params": params or {}})


def tool(name, arguments=None, rid=1) -> dict:
    return call("tools/call", {"name": name, "arguments": arguments or {}}, rid)


def payload(reply: dict):
    """Decode the text content of a successful tool reply."""
    assert reply["result"]["isError"] is False
    return json.loads(reply["result"]["content"][0]["text"])


# ------------------------------------------------------------------------ handshake

def test_initialize_advertises_the_version_and_the_report_schema():
    r = call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}})
    info = r["result"]["serverInfo"]
    assert info["name"] == "firmprint" and info["reportSchema"] == "firmprint-report/1"
    assert r["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert "contract.violations" in r["result"]["instructions"]


def test_ping_and_notifications_follow_the_rules():
    assert call("ping")["result"] == {}
    assert mcp.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert mcp.dispatch({"jsonrpc": "2.0", "id": 7, "method": "notifications/cancelled"}) is None


def test_an_unknown_method_is_a_jsonrpc_error_not_a_result():
    r = call("tools/nothing")
    assert r["error"]["code"] == -32601 and "tools/nothing" in r["error"]["message"]
    assert "result" not in r


def test_the_tool_list_matches_the_dispatch_table():
    tools = call("tools/list")["result"]["tools"]
    assert [t["name"] for t in tools] == ["firmprint_scan", "firmprint_verify",
                                          "firmprint_socdb_list", "firmprint_socdb_show"]
    for t in tools:
        schema = t["inputSchema"]
        assert schema["type"] == "object" and t["description"]
        # a client builds its call from this schema; a required key it cannot find in
        # properties would be impossible to satisfy
        assert set(schema.get("required", [])) <= set(schema["properties"])


@pytest.mark.parametrize("name", ["firmprint_scan", "firmprint_verify"])
def test_a_missing_path_is_a_call_error_not_an_internal_one(name):
    """-32603 tells the agent "the server broke"; this call is the agent's mistake and
    has to be labelled that way, or a model retries it forever."""
    r = tool(name)
    assert r["error"]["code"] == -32602
    assert "path" in r["error"]["message"]


def test_socdb_show_without_a_device_names_the_argument_it_wants():
    r = tool("firmprint_socdb_show", {"address": "0x4001100C"})
    assert r["error"]["code"] == -32602 and "device" in r["error"]["message"]


# --------------------------------------------------------------------------- errors

def test_an_unknown_tool_is_refused_before_any_file_is_opened():
    r = tool("firmprint_wipe_disk")
    assert r["error"]["code"] == -32602 and "unknown tool" in r["error"]["message"]


def test_a_missing_path_is_an_invalid_params_error():
    assert tool("firmprint_scan", {})["error"]["code"] == -32602


def test_a_missing_file_is_an_internal_error_that_names_the_file():
    r = tool("firmprint_scan", {"path": "nowhere.bin"})
    assert r["error"]["code"] == -32603
    assert "nowhere.bin" in r["error"]["message"]


# ---------------------------------------------------------------------- the database

def test_socdb_show_resolves_an_address_without_reading_a_file():
    out = payload(tool("firmprint_socdb_show", {"device": "stm32f427xx",
                                                "address": "0x4001100C"}))
    assert out["block"] == "USART1" and out["register"] == "CR1"
    assert out["offset_in_block"] == "0x000C" and out["is_peripheral"] is True


def test_socdb_show_says_nothing_was_found_instead_of_guessing_a_block():
    out = payload(tool("firmprint_socdb_show", {"device": "stm32f427xx",
                                                "address": "0x12345678"}))
    assert out["block"] is None and "no mapped block" in out["note"]


def test_socdb_show_without_an_address_returns_the_map_summary():
    out = payload(tool("firmprint_socdb_show", {"device": "stm32h743xx"}))
    assert out["device"] == "stm32h743xx" and out["peripherals"] > 50


def test_socdb_show_rejects_an_address_that_is_not_a_number():
    assert tool("firmprint_socdb_show", {"device": "stm32f427xx",
                                         "address": "GPIOA"})["error"]["code"] == -32602


def test_socdb_list_carries_the_provenance_a_reviewer_needs():
    rows = payload(tool("firmprint_socdb_list"))
    assert {r["device"] for r in rows} >= {"stm32f427xx", "stm32h743xx"}
    for r in rows:
        assert r["provenance"]["header_sha256"] and r["provenance"]["source_repo"]
        assert r["peripheral_blocks"] > 50


@pytest.mark.parametrize("raw,expected", [("0x4001100C", 0x4001100C), (0x4001100C, 0x4001100C),
                                          ("64", 64), ("0x10", 16)])
def test_addresses_accept_both_notations(raw, expected):
    assert mcp._as_int(raw) == expected


@pytest.mark.parametrize("raw", ["", "GPIOA", "4001100C", "0xZZ", "1,2"])
def test_an_unparsable_address_is_a_call_error_not_a_zero(raw):
    """A bare `4001100C` reads as hex to a human and as a syntax error to int();
    refusing the call beats silently answering for address 0."""
    with pytest.raises(mcp._Bad) as excinfo:
        mcp._as_int(raw)
    assert excinfo.value.code == -32602


@pytest.mark.parametrize("raw", [None, True, False])
def test_number_parsing_keeps_bool_out_of_the_address_space(raw):
    assert mcp._as_int(raw) is None


# ---------------------------------------------------------------------------- scans

@pytest.fixture
def dump(tmp_path):
    g, u = 0x4002_0000, 0x4001_1000
    data = cortex_m_image(base=0x0800_0000, code_bytes=0x400)
    data = data[:0x200] + struct.pack("<2I", g, u + 0x0C) + data[0x208:]
    p = tmp_path / "dump.bin"
    p.write_bytes(data)
    return p


def test_a_scan_reply_keeps_the_contract_and_the_offsets(dump):
    report = payload(tool("firmprint_scan", {"path": str(dump), "no_code": True}))
    assert report["schema"] == "firmprint-report/1"
    assert report["contract"]["violations"] == []
    assert report["meta"]["engines"]["carve"] == "carve/1"
    kinds = {f["kind"] for f in report["findings"]}
    assert {"cortex-m.vector_table", "peripheral.usage"} <= kinds
    word = next(e for f in report["findings"] if f["kind"] == "peripheral.usage"
                for e in f["evidence"])
    assert word["bytes"] and word["file_offset"] is not None


def test_max_findings_trims_the_payload_and_says_so(dump):
    report = payload(tool("firmprint_scan", {"path": str(dump), "no_code": True,
                                             "max_findings": 2}))
    assert len(report["findings"]) == 2
    assert report["meta"]["findings_truncated_to"] == 2


def test_markdown_format_is_a_string_not_an_object(dump):
    reply = tool("firmprint_scan", {"path": str(dump), "no_code": True,
                                   "format": "markdown"})
    text = reply["result"]["content"][0]["text"]
    assert text.startswith("# firmprint report")
    assert "contract: 0 violation(s)" in text


# --------------------------------------------------------------------------- plumbing

def test_read_messages_skips_blank_and_unparsable_lines():
    stream = io.StringIO('\n{"jsonrpc":"2.0","id":1,"method":"ping"}\nnope\n\n')
    assert [m["id"] for m in mcp.read_messages(stream)] == [1]


def test_serve_writes_one_reply_per_request_and_counts_them():
    class Out:
        def __init__(self):
            self.lines = []

        def write(self, text):
            self.lines.append(text)

        def flush(self):
            pass

    inbox = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
                        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
                        '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
    out = Out()
    assert mcp.serve(inbox, out) == 2
    assert [json.loads(line)["id"] for line in out.lines] == [1, 2]
    assert all(line.endswith("\n") for line in out.lines)


def test_the_bundled_self_test_passes():
    assert mcp.main(["--self-test"]) == 0
