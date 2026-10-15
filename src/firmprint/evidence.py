"""Evidence-recorded findings.

firmprint's contract, borrowed from the best part of agent-era RE tooling: a
claim without reproducible bytes is not a finding.  Every Finding carries the
file offset, virtual address and raw bytes that produced it, plus an explicit
list of what the analysis could *not* establish.

`validate()` is fail-closed: a high-confidence claim with no evidence is an
error, not a warning.  Flip it off with --no-strict only if you know why.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = "firmprint-finding/1"

#: findings at or above this confidence must carry reproducible evidence
STRICT_CONFIDENCE = 0.6


def sha256_file(source: bytes | str | Path) -> str:
    """Digest of a buffer or a file — the report hashes bytes, not names."""
    h = hashlib.sha256()
    if isinstance(source, (bytes, bytearray)):
        h.update(source)
    else:
        with open(source, "rb") as fh:
            h.update(fh.read())
    return h.hexdigest()


@dataclass(slots=True)
class Evidence:
    """One reproducible observation.  Keep it small enough to render in a terminal."""

    kind: str                          # bytes | word | string | region | instruction | symbol
    note: str = ""
    file_offset: int | None = None
    vaddr: int | None = None
    hex: str | None = None
    text: str | None = None
    count: int | None = None

    def to_dict(self) -> dict:
        out = {"kind": self.kind, "note": self.note}
        if self.file_offset is not None:
            out["file_offset"] = self.file_offset
        if self.vaddr is not None:
            out["vaddr"] = f"0x{self.vaddr:08X}"
        if self.hex is not None:
            out["bytes"] = self.hex
        if self.text is not None:
            out["text"] = self.text
        if self.count is not None:
            out["count"] = self.count
        return out


@dataclass(slots=True)
class Finding:
    kind: str                          # cortex-m.vector_table | soc.candidate | peripheral.usage | ...
    subject: str                       # what the claim is about, e.g. "USART1"
    confidence: float                  # 0..1, see rule docstrings for how it is built
    summary: str
    engine: str                        # carve/1 | capstone/1 | vectors/1 | container/1
    rule: str                          # machine-readable rule id, stable across releases
    evidence: list[Evidence] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def add(self, ev: Evidence) -> Finding:
        self.evidence.append(ev)
        return self

    def to_dict(self, fid: str | None = None) -> dict:
        out = {
            "kind": self.kind,
            "subject": self.subject,
            "confidence": round(self.confidence, 3),
            "summary": self.summary,
            "engine": self.engine,
            "rule": self.rule,
            "evidence": [e.to_dict() for e in self.evidence[:12]],
            "evidence_total": len(self.evidence),
            "unknowns": self.unknowns,
            "metrics": self.metrics,
        }
        if fid:
            out["id"] = fid
        return out


def validate(findings: Iterable[Finding]) -> list[str]:
    """Return human-readable contract violations (empty == report is trustworthy)."""
    problems = []
    for f in findings:
        strict = f.confidence >= STRICT_CONFIDENCE
        if strict and not f.evidence:
            problems.append(f"{f.kind}/{f.subject}: confidence {f.confidence:.2f} but zero evidence")
        # An evidence list full of un-anchored notes is decoration, not proof: a
        # reader cannot go and check it.  Confident claims need at least one item
        # that names a place.
        if strict and f.evidence and not any(e.file_offset is not None or e.vaddr is not None
                                             for e in f.evidence):
            problems.append(f"{f.kind}/{f.subject}: confidence {f.confidence:.2f} but no "
                            f"evidence carries a file offset or virtual address")
        if f.confidence > 1.0 or f.confidence < 0.0:
            problems.append(f"{f.kind}/{f.subject}: confidence out of range")
        for e in f.evidence:
            if e.kind in ("bytes", "word") and not e.hex:
                problems.append(f"{f.kind}/{f.subject}: {e.kind} evidence missing bytes")
            if e.kind == "word" and e.file_offset is None:
                problems.append(f"{f.kind}/{f.subject}: word evidence missing file offset")
    return problems


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False, default=str) + "\n"


def iter_numbered(findings: Iterable[Finding]):
    """Stable finding ids: F-0001 in report order (sorted by confidence desc, kind)."""
    ordered = sorted(findings, key=lambda f: (-f.confidence, f.kind, f.subject))
    for n, f in enumerate(ordered, 1):
        yield f"F-{n:04d}", f
