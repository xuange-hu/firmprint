#!/usr/bin/env python3
"""Fetch the OpenMV firmware samples used by the verification documents, by digest.

Why a fetcher instead of a committed binary: the images are build artifacts of OpenMV
firmware (an STM32F427 camera and an STM32F765 one), and the repository should not ship
third-party binaries it cannot re-license.  `NOTICE.md` records what upstream actually says
about its licensing and what we checked and could not establish; it deliberately does not
call these images "MIT", and nothing here should repeat that claim.

Why a *tagged release* and a hard digest check, rather than the `development` asset this
script used to read: `development` is a rolling prerelease, republished on every upstream
commit.  On 2026-10-18 those assets moved under us, CI scanned a build other than the one
`verification/*.md` describes, and the doc-quote gate reported "the prose is stale".  That
was true in the narrow sense and misleading in the useful one: the prose was fine and the
*bytes* had moved.  A tool that fetches an answer key has to refuse to substitute it, so:

  * the URL names an immutable tag (`v5.0.1`), not a branch-shaped moving target;
  * the archive is checked against a pinned sha256;
  * every file written is checked against its own pinned sha256, because an archive digest
    cannot tell you that the `firmware.bin` inside it is the one the documents quoted;
  * a mismatch exits non-zero instead of printing a note and carrying on;
  * files already on disk are accepted only when they *verify*, not when they merely exist.

    python tools/get_sample.py                       # -> samples/openmv2/*
    python tools/get_sample.py --board OPENMV3       # -> samples/openmv3/*
    python tools/get_sample.py --all                 # both boards, one download
    python tools/get_sample.py --check               # are the samples the pinned build?
    python tools/get_sample.py --all --force         # refetch, re-checking every digest

Re-pinning after an intentional move -- the only workflow that changes what the answer key
describes -- is one copy-paste:

    python tools/get_sample.py --all --force --allow-drift --show-pins
    python tools/make_verification.py                # regenerate the documents
    python tools/check_doc_quotes.py                 # and the prose that quotes them

Nothing here sends anything anywhere except a single HTTPS GET to GitHub.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The release this answer key describes.  A tag, because a reader in a year has to be able
#: to fetch the same bytes the documents quote: a `development` asset cannot be re-fetched
#: once upstream rebuilds it, which makes every number in `verification/` unreproducible.
RELEASE = "v5.0.1"
ASSET = f"https://github.com/openmv/openmv/releases/download/{RELEASE}/firmware_{RELEASE}.zip"
#: The published archive, pinned.  A tagged release must not move, so a mismatch here is
#: reported as the supply-chain event it would be -- see the module docstring.
#:
#: Computed from the asset GitHub served for `v5.0.1` on 2026-10-18: 90,999,894 bytes, the
#: only asset on that release.  `--check` re-verifies the six board files, not this.
ASSET_SHA256 = "1338b9607b57d88cf1de5aee115ea0e18cb17d06ff4d8dc55d6c022dba66dbc8"

#: The files the scanner and the answer key use.  `romfs.stamp` is a zero-byte marker and
#: is deliberately not among them: pinning an empty file proves nothing.
WANTED = ("firmware.elf", "firmware.bin", "openmv.bin", "bootloader.elf",
          "bootloader.bin", "romfs0.img")

#: board -> (directory inside the archive, destination, {file: sha256})
#:
#: One bundle carries every OpenMV target and the same file names appear in each board's
#: directory, so extraction selects by *path*: a fetcher that matched `firmware.bin` by
#: basename alone would write whichever board came first in the archive.
BOARDS: dict[str, tuple[str, Path, dict[str, str]]] = {
    "OPENMV2": (
        "OPENMV2", ROOT / "samples" / "openmv2",
        {
            "firmware.elf": "e2f1cc135d32d733371f19a779fa0202e8a1b3d96ddc056d5e1601b24665e6f3",
            "firmware.bin": "7aa2b5364d124e3b5ae0d6595cb41b557bf32b646ab59201165dbe6a59e20a1e",
            "openmv.bin": "5bd1d1b26e5b0766816fd09faa914f8b63455f47b2a3517226c67ec59d12afa3",
            "bootloader.elf": "759832db9f696d4de0b318bbf7c05030a29814c4e62d51ee56030aeccbd36ad2",
            "bootloader.bin": "e2cce5ecb67bbbe851ba3e7bcdaf0a4819dcf6a065db2adb931ca190fa30d2b1",
            "romfs0.img": "a042465686ad93c0fc437daf9c2536bb3bb5a853841ed14715292be86c277c30",
        },
    ),
    "OPENMV3": (
        "OPENMV3", ROOT / "samples" / "openmv3",
        {
            "firmware.elf": "97e6d7a61947a48d4e367f703f26c66a46cd28b132c8395bc7c0a3a3ae38fbed",
            "firmware.bin": "740c1b35e712c9bd1430e59eed86e60c36ff662ca383933309d3c9cfb83496c1",
            "openmv.bin": "d97151055649f737b4b9cc1fa0edf0f5f9c3afd439cb1ac87e6591e9ae51cd03",
            "bootloader.elf": "029daa756511c7f876d7d3595c6776d71bbccea7bf0d9a84bd42199bbd34804b",
            "bootloader.bin": "2d9237bc5ad4df17b237ed72e75724bd02531dc71e510b4fe378e067572c038f",
            "romfs0.img": "015e0445065408cec38fd1d38914193e5e46c7d9d11a280e6c1ddc7aebb0835f",
        },
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_of(path: Path) -> str | None:
    """The file's digest, or None when the file is absent -- None never equals a pin."""
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def on_disk(dest: Path, pins: dict[str, str]) -> list[str]:
    """Files for one board that are missing or are not the pinned bytes.

    Empty means the directory holds exactly the pinned build, and that is the only reason
    a download may be skipped: `exists()` used to be the test, so a stale directory looked
    like proof that the answer key was reproducible when it was proof of nothing.
    """
    out = []
    for name, want in pins.items():
        got = digest_of(dest / name)
        if got is None:
            out.append(f"  {name:<15} missing (pinned {want[:16]}...)")
        elif got != want:
            out.append(f"  {name:<15} sha256 {got[:16]}... != pinned {want[:16]}...")
    return out


def download(url: str, timeout: int = 900) -> bytes:
    """Fetch with curl (proxy/CA setup on real machines is rarely urllib-friendly)."""
    cmd = ["curl", "-sSL", "--fail", "--retry", "2", "-m", str(timeout), url]
    proc = subprocess.run(cmd, capture_output=True, check=False)
    if proc.returncode:
        raise SystemExit(f"download failed ({proc.returncode}): "
                         f"{proc.stderr.decode(errors='replace')[:200]}\n"
                         f"network or proxy problem - the URL is {url}")
    return proc.stdout


def board_members(z: zipfile.ZipFile, prefix: str) -> dict[str, bytes]:
    """The wanted files of one board, keyed by name, read from `<prefix>/` only."""
    want = f"{prefix}/"
    out: dict[str, bytes] = {}
    for n in z.namelist():
        if n.startswith(want):
            base = n[len(want):]
            if base in WANTED:
                out[base] = z.read(n)
    return out


def pins_snippet(prefix: str, members: dict[str, bytes]) -> str:
    """The `BOARDS` entry for a fetched build, paste-ready.

    Re-pinning is the one operation that changes what the answer key claims, so this prints
    it rather than leaving a reader to compute six digests with a second tool.
    """
    body = "\n".join(f'            "{name}": "{sha256(members[name])}",'
                     for name in WANTED if name in members)
    return (f'    "{prefix}": (\n        "{prefix}", ROOT / "samples" / "{prefix.lower()}",'
            f"\n        {{\n{body}\n        }},\n    ),")


#: what to tell a reader when the bytes available are not the bytes the documents quote
REFUSAL = ("  Refusing to substitute: `verification/*.md`, the README and the case studies "
           "quote numbers from the pinned build, and writing these files would leave the "
           "answer key describing bytes it never scanned.  If the move is intentional "
           "(you chose a different release), re-run with --allow-drift --show-pins, paste "
           "the printed digests into BOARDS above, then run tools/make_verification.py and "
           "fix the prose tools/check_doc_quotes.py reports as stale.  If it is not, treat "
           "it as the supply-chain event it is and say so in the pull request.")


def moved(expected: str, got: str, what: str) -> str:
    """The message for an asset whose bytes are not the pinned ones."""
    return (f"{what} is not the pinned build\n"
            f"  pinned {expected}\n"
            f"  got    {got}\n"
            f"  A tagged release must not move: if this prints, upstream re-pointed the tag "
            f"or replaced the asset. " + REFUSAL)



def unpinned(board: str, dest: Path) -> str:
    """Refuse to report a pass over files this file never pinned.

    A check that prints "pinned build present" while its pin table is empty is worse than
    no check: it is the claim the tool was written to make, made without the evidence.
    """
    return (f"[{board}] {dest} cannot be verified: tools/get_sample.py holds no pinned "
            f"digests for this board")



def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--board", choices=sorted(BOARDS), default="OPENMV2",
                    help="which OpenMV target to fetch (default: OPENMV2)")
    ap.add_argument("--all", action="store_true",
                    help=f"fetch every board: {', '.join(sorted(BOARDS))}")
    ap.add_argument("--force", action="store_true",
                    help="download again even if the pinned files are already on disk")
    ap.add_argument("--allow-drift", action="store_true",
                    help="write a build whose digest differs from the pin (the re-pin step)")
    ap.add_argument("--show-pins", action="store_true",
                    help="print the paste-ready BOARDS entry for whatever was fetched")
    ap.add_argument("--check", action="store_true",
                    help="only report whether the samples on disk are the pinned build")
    ap.add_argument("--url", default=None, help="fetch from a mirror instead of ASSET")
    ap.add_argument("--digest", default=None, help="archive digest to check --url against")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()

    boards = sorted(BOARDS) if a.all else [a.board]
    rc = 0

    if a.check:
        for b in boards:
            _prefix, dest, pins = BOARDS[b]
            if not pins:
                print(unpinned(b, dest), file=sys.stderr)
                rc = 1
                continue
            bad = on_disk(dest, pins)
            print(f"[{b}] {dest}: "
                  f"{'pinned build present' if not bad else 'NOT the pinned build'}")
            for line in bad:
                print(line)
            rc = 1 if bad else rc
        return rc

    # one download serves every requested board; it happens only when a board fails to verify
    stale = [b for b in boards if not BOARDS[b][2] or on_disk(BOARDS[b][1], BOARDS[b][2])]
    need = boards if a.force else stale
    for b in boards:
        if b in need:
            continue
        _prefix, dest, pins = BOARDS[b]
        print(f"[{b}] {dest} already holds the pinned build "
              f"({len(pins)} file(s) verified by sha256); --force to refetch")
        for name in WANTED:
            p = dest / name
            d = digest_of(p)
            print(f"  {name:<15} {p.stat().st_size:>9,} bytes  sha256 {d[:16]}"
                  if d else f"  {name:<15} absent")

    if not need:
        print("\nnext: python -m pytest   ·   python tools/check_doc_quotes.py")
        return 0

    # refusing before the transfer, not after it: a board with no pins cannot be verified, and
    # downloading 91 MB to discover that is a slow way to learn what the file already says
    if not a.show_pins:
        bare = [b for b in need if not BOARDS[b][2]]
        if bare:
            for b in bare:
                print(unpinned(b, BOARDS[b][1]), file=sys.stderr)
            print("  Nothing was downloaded.  To establish pins for a new build -- the only "
                  "operation that rewrites what the answer key describes -- run with "
                  "--show-pins.", file=sys.stderr)
            return 1

    print(f"[{','.join(need)}] fetching {a.url or ASSET}")
    blob = download(a.url or ASSET, a.timeout)
    got = sha256(blob)
    expect = a.digest or ASSET_SHA256
    print(f"  {len(blob):,} bytes, sha256 {got}")
    if not expect:
        print("  no archive digest is pinned in this file, so the download is unchecked",
              file=sys.stderr)
    elif got != expect:
        print(moved(expect, got, f"release {RELEASE}"), file=sys.stderr)
        if not a.allow_drift:
            return 1

    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for b in need:
            prefix, dest, pins = BOARDS[b]
            members = board_members(z, prefix)
            missing = [n for n in WANTED if n not in members]
            if missing:
                top = sorted({n.split("/")[0] for n in z.namelist() if "/" in n})[:8]
                print(f"[{b}] archive layout changed: no {', '.join(missing)} under "
                      f"{prefix}/; top-level entries were {top}", file=sys.stderr)
                return 2
            if not pins and not a.show_pins:
                print(unpinned(b, dest), file=sys.stderr)
                return 1
            drift = [f"  {prefix}/{name}: pinned {pins[name][:16]}... got "
                     f"{sha256(members[name])[:16]}..." for name in pins
                     if sha256(members[name]) != pins[name]]
            if drift and not a.allow_drift:
                print(f"[{b}] this build is not the one the answer key describes "
                      f"({len(drift)} of {len(pins)} pinned file(s) differ); nothing was "
                      f"written for {b}:\n" + "\n".join(drift) + "\n" + REFUSAL,
                      file=sys.stderr)
                return 1
            dest.mkdir(parents=True, exist_ok=True)
            for name, data in members.items():
                (dest / name).write_bytes(data)
            print(f"[{b}] unpacked into {dest}:")
            for name in WANTED:
                print(f"  {name:<15} {(dest / name).stat().st_size:>9,} bytes  "
                      f"sha256 {sha256(members[name])[:16]}")
            if drift:
                print(f"[{b}] DIGESTS MOVED ({len(drift)} file(s)); paste this into BOARDS "
                      f"in tools/get_sample.py, then regenerate the answer key:\n"
                      + pins_snippet(prefix, members), file=sys.stderr)
                rc = 1
            elif a.show_pins:
                print(pins_snippet(prefix, members))
    print("\nnext: python tools/make_verification.py   ·   python tools/check_doc_quotes.py")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
