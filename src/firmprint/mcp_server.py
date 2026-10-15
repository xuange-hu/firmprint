"""stdio MCP server: expose firmprint to an agent without a shell.

The point of an evidence-recorded report is that something other than a human can
check it.  A model can call `firmprint.scan`, get offsets and bytes back, and quote
them; it cannot make the tool claim more than the carve found, because the contract
travels inside the payload (`contract.violations`).

Wire format is MCP over stdio: newline-delimited JSON-RPC 2.0, one object per line,
no LSP-style headers.  Everything is read-only and offline — no network calls, no
writes, and the only paths it touches are the ones the caller names.

Run it with `firmprint mcp`, or register it in a client as:

    {"command": "firmprint", "args": ["mcp"], "type": "stdio"}
"""
from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from typing import Any, TextIO

from . import __version__
from .analyze import SCHEMA, analyze, to_markdown
from .socdb import DATA_DIR, available, load_soc
from .verify import compare, symbol_oracle

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "firmprint"

#: capstone decoding is the slow part; an agent loop should not inherit it by accident
DEFAULT_BUDGET = 0x8_0000

TOOLS: list[dict] = [
    {
        "name": "firmprint_scan",
        "description": ("Identify a Cortex-M firmware image: container, load base, SoC "
                        "candidates and peripheral usage. Every finding carries the file "
                        "offset and raw bytes that produced it, plus what the tool could "
                        "not prove (`unknowns`) and a self-check (`contract.violations`)."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "firmware file: .elf/.bin/.hex/.uf2"},
                "soc": {"type": "string", "description": "force a database, e.g. stm32f427xx"},
                "base": {"type": "string", "description": "load address for raw dumps, 0x-hex"},
                "full": {"type": "boolean", "description": "decode all code, ignore the budget"},
                "budget": {"type": "integer", "description": "capstone byte budget"},
                "no_code": {"type": "boolean", "description": "skip instruction decoding"},
                "format": {"type": "string", "enum": ["json", "markdown"],
                           "description": "json (default) or a human summary"},
                "max_findings": {"type": "integer",
                                 "description": "trim the finding list (json only)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "firmprint_verify",
        "description": ("Score a scan against an independent answer key: the image's own "
                        "HAL/LL symbol families. Returns confirmed/missed per driver "
                        "module. Only works on images that carry function symbols."),
        "inputSchema": {"type": "object",
                        "properties": {"path": {"type": "string"},
                                       "soc": {"type": "string"},
                                       "full": {"type": "boolean"}},
                        "required": ["path"]},
    },
    {
        "name": "firmprint_socdb_list",
        "description": "List the installed memory-map databases and their provenance.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "firmprint_socdb_show",
        "description": ("Resolve one address against one database: which peripheral block "
                        "contains it and which register the offset names. Use this to check "
                        "a claim in a report without re-running a scan."),
        "inputSchema": {"type": "object",
                        "properties": {"device": {"type": "string"},
                                       "address": {"type": "string",
                                                   "description": "0x-hex, e.g. 0x4001100C"}},
                        "required": ["device"]},
    },
]


def dispatch(request: dict) -> dict | None:
    """Handle one JSON-RPC call.  Notifications (no id) get no reply."""
    method = request.get("method")
    rid = request.get("id")
    params = request.get("params") or {}
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    try:
        result = _call(method, params)
    except _Bad as bad:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": bad.code, "message": str(bad)}}
    except Exception as exc:                              # noqa: BLE001 - reported, not raised
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32603, "message": f"{type(exc).__name__}: {exc}"}}
    if rid is None:
        return None
    return {"jsonrpc": "2.0", "id": rid, "result": result}


class _Bad(Exception):
    def __init__(self, message: str, code: int = -32602):
        super().__init__(message)
        self.code = code


def _call(method: str, params: dict) -> Any:
    if method == "initialize":
        return {"protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": __version__,
                               "reportSchema": SCHEMA},
                "instructions": ("Read-only firmware identification. Reports carry file "
                                 "offsets and raw bytes; check contract.violations before "
                                 "quoting a finding, and quote unknowns when you hedge.")}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        return _tool(params.get("name"), params.get("arguments") or {})
    raise _Bad(f"method not found: {method!r}", -32601)


#: which argument each tool cannot work without; a missing one is a call error (-32602),
#: not a KeyError dressed up as an internal error (-32603)
REQUIRED_ARGUMENT = {"firmprint_scan": "path", "firmprint_verify": "path",
                    "firmprint_socdb_show": "device"}


def _tool(name: str | None, args: dict) -> dict:
    if name not in {t["name"] for t in TOOLS}:
        raise _Bad(f"unknown tool: {name!r}", -32602)
    need = REQUIRED_ARGUMENT.get(name)
    if need and not args.get(need):
        raise _Bad(f"{name} needs a `{need}`")
    if name == "firmprint_socdb_list":
        payload: Any = _socdb_list()
    elif name == "firmprint_socdb_show":
        payload = _socdb_show(args["device"], args.get("address"))
    elif name == "firmprint_verify":
        payload = _verify(args["path"], args.get("soc"), bool(args.get("full")))
    else:
        payload = _scan(args)
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=1, default=str)
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _scan(args: dict) -> Any:
    report = analyze(args["path"], soc_name=args.get("soc"),
                     base=_as_int(args.get("base")), data_dir=DATA_DIR,
                     budget=args.get("budget") or DEFAULT_BUDGET,
                     full=bool(args.get("full")), skip_code=bool(args.get("no_code")))
    if args.get("format") == "markdown":
        return to_markdown(report)
    if args.get("max_findings"):
        n = int(args["max_findings"])
        report = {**report, "findings": report["findings"][:n],
                  "meta": {**report["meta"], "findings_truncated_to": n}}
    return report


def _verify(path: str, soc: str | None, full: bool) -> dict:
    report = analyze(path, soc_name=soc, full=full)
    from .container import load
    symbols = load(path).symbols
    modules, samples = symbol_oracle(symbols)
    result = compare(report, modules)
    result["symbol_count"] = len(symbols)
    result["oracle_sample_symbols"] = samples
    result["contract_violations"] = report["contract"]["violations"]
    return result


def _socdb_list() -> list[dict]:
    out = []
    for n in available():
        s = load_soc(n).summary()
        out.append({"device": s["device"], "family": s["family"], "core": s["core"],
                    "peripheral_blocks": s["peripherals"], "register_structs": s["struct_types"],
                    "provenance": s["provenance"]})
    return out


def _socdb_show(device: str, address: str | None) -> dict:
    soc = load_soc(device)
    if not address:
        return soc.summary()
    value = _as_int(address)
    if value is None:
        raise _Bad(f"address must be 0x-hex or an integer, got {address!r}")
    hit = soc.peripheral_at(value)
    out: dict[str, Any] = {"address": f"0x{value:08X}", "device": device}
    if not hit:
        out["block"] = None
        out["note"] = "no mapped block contains this address in this database"
        return out
    periph, delta = hit
    out.update({"block": periph, "block_base": f"0x{soc.peripherals[periph]['base']:08X}",
                "offset_in_block": f"0x{delta:04X}",
                "register": soc.register_name(periph, delta),
                "is_peripheral": soc.is_peripheral(periph),
                "declared_size": soc.peripherals[periph].get("size")})
    return out


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith(("0x", "-0x")) else int(text)
    except ValueError:
        raise _Bad(f"not a number: {value!r}") from None


def read_messages(stream: TextIO) -> Iterator[dict]:
    """Newline-delimited JSON-RPC.  A blank or unparsable line is skipped, not fatal."""
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            sys.stderr.write("firmprint-mcp: skipping unparsable line\n")
            continue
        if isinstance(msg, dict):
            yield msg


def serve(stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Serve until stdin closes.  Returns the number of replies written."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    n = 0
    for msg in read_messages(stdin):
        reply = dispatch(msg)
        if reply is None:
            continue
        stdout.write(json.dumps(reply, default=str) + "\n")
        stdout.flush()
        n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    if "--self-test" in args:
        return _self_test()
    try:
        sys.stdout.reconfigure(encoding="utf8")
    except Exception:                                    # noqa: BLE001 - cosmetic
        pass
    sys.stderr.write(f"firmprint mcp: ready on stdio ({__version__}, schema {SCHEMA})\n")
    serve()
    sys.stderr.write("firmprint mcp: stdin closed\n")
    return 0


def _self_test() -> int:
    """Round-trip the protocol in-memory; used by CI and by `firmprint mcp --self-test`."""
    lines = [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
             json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
             json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
             json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "firmprint_socdb_show",
                                    "arguments": {"device": "stm32f427xx",
                                                  "address": "0x4001100C"}}}),
             json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                         "params": {"name": "firmprint_socdb_list", "arguments": {}}}),
             "this is not json",
             json.dumps({"jsonrpc": "2.0", "id": 5, "method": "nope"}),
             json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                         "params": {"name": "firmprint_scan",
                                    "arguments": {"path": "does-not-exist.bin"}}})]

    class Out:
        def __init__(self) -> None:
            self.rows: list[dict] = []

        def write(self, text: str) -> None:
            self.rows.append(json.loads(text))

        def flush(self) -> None:
            pass

    import io

    out = Out()
    # The fixture feeds `"this is not json"` on purpose, so the "skipping unparsable
    # line" note on stderr is the pass condition, not a warning: a server that died on
    # garbage would fail the `wrote == 6` assert below instead.
    sys.stderr.write("firmprint mcp: self-test fixture includes one unparsable line\n")
    wrote = serve(io.StringIO("\n".join(lines) + "\n"), out)
    by_id = {r["id"]: r for r in out.rows}
    assert wrote == 6 and len(out.rows) == 6, (wrote, len(out.rows))
    assert by_id[1]["result"]["serverInfo"]["name"] == SERVER_NAME
    assert len(by_id[2]["result"]["tools"]) == len(TOOLS)
    show = json.loads(by_id[3]["result"]["content"][0]["text"])
    assert show["block"] == "USART1" and show["register"] == "CR1", show
    assert by_id[4]["result"]["content"][0]["text"].lstrip().startswith("[")
    assert by_id[5]["error"]["code"] == -32601, by_id[5]
    assert by_id[6]["error"]["code"] == -32603 and "does-not-exist" in by_id[6]["error"]["message"]
    print(f"mcp self-test ok: {len(TOOLS)} tools, {wrote} replies, "
          f"protocol {PROTOCOL_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
