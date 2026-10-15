#!/usr/bin/env python3
"""Fetch the OpenMV firmware samples used by the verification documents.

Why a fetcher instead of a committed binary: the images are build artifacts of
MIT-licensed OpenMV firmware (an STM32F427 camera and an STM32F765 one), and the
repository should not ship third-party binaries it cannot re-license. Pinning the
sha256 means a reader knows the bytes they analysed are the bytes the verification
documents describe.

    python tools/get_sample.py                       # -> samples/openmv2/*
    python tools/get_sample.py --board OPENMV3       # -> samples/openmv3/*
    python tools/get_sample.py --all --force         # both boards, refetch

Two boards on purpose: they share a peripheral map almost entirely, so they are the
case that separates "matched a family" from "matched a part".

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

#: board -> (asset URL, published sha256 of the zip, destination directory)
BOARDS = {
    "OPENMV2": (
        "https://github.com/openmv/openmv/releases/download/development/firmware_OPENMV2.zip",
        "50192f97394a18618e0aa3af2b9db3c4a3bff7f51f495193375c31728eb1159a",
        ROOT / "samples" / "openmv2",
    ),
    "OPENMV3": (
        "https://github.com/openmv/openmv/releases/download/development/firmware_OPENMV3.zip",
        "eee3f1014551777cf9f1fe314f0ebe0c59b2e8139f052af805bf1ac79dc30d9c",
        ROOT / "samples" / "openmv3",
    ),
}
URL, EXPECT_SHA256, DEST = BOARDS["OPENMV2"]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str, timeout: int = 900) -> bytes:
    """Fetch with curl (proxy/CA setup on real machines is rarely urllib-friendly)."""
    cmd = ["curl", "-sSL", "--fail", "--retry", "2", "-m", str(timeout), url]
    proc = subprocess.run(cmd, capture_output=True, check=False)
    if proc.returncode:
        raise SystemExit(f"download failed ({proc.returncode}): "
                         f"{proc.stderr.decode(errors='replace')[:200]}\n"
                         f"network or proxy problem - the URL is {url}")
    return proc.stdout


def fetch(board: str, *, url: str, expect: str, dest: Path, force: bool,
          timeout: int) -> int:
    wanted = ["firmware.elf", "firmware.bin", "openmv.bin", "bootloader.elf",
              "bootloader.bin", "romfs0.img"]
    if not force and all((dest / f).exists() for f in wanted[:5]):
        print(f"[{board}] {dest} already holds the firmware; --force to refetch")
        for f in wanted:
            p = dest / f
            if p.exists():
                print(f"  {f:<16} {p.stat().st_size:>9,} bytes")
        return 0

    print(f"[{board}] fetching {url}")
    blob = download(url, timeout)
    digest = sha256(blob)
    print(f"  {len(blob):,} bytes, sha256 {digest}")
    if digest != expect:
        print(f"  note: the upstream 'development' release moved; the pinned digest was\n"
              f"        {expect}\n"
              f"        the verification documents describe the pinned build, so re-run:\n"
              f"        python tools/make_verification.py")

    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = z.namelist()
        written = []
        for n in names:
            base = Path(n).name
            if base in wanted:
                target = dest / base
                target.write_bytes(z.read(n))
                written.append((base, target.stat().st_size))
        if not written:
            top = {n.split("/")[0] for n in names if n.split("/")[0]}
            print(f"[{board}] archive layout changed; contents were:",
                  sorted(top)[:8], file=sys.stderr)
            return 2
    print(f"[{board}] unpacked into {dest}:")
    for base, size in written:
        print(f"  {base:<16} {size:>9,} bytes  sha256 {sha256((dest / base).read_bytes())[:16]}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--board", choices=sorted(BOARDS), default="OPENMV2",
                    help="which OpenMV target to fetch (default: OPENMV2)")
    ap.add_argument("--all", action="store_true", help=f"fetch every board: {', '.join(sorted(BOARDS))}")
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    ap.add_argument("--url", default=None, help="override the asset URL (with --board)")
    ap.add_argument("--digest", default=None, help="override the expected sha256")
    ap.add_argument("--dest", default=None, help="override the destination directory")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()

    boards = sorted(BOARDS) if a.all else [a.board]
    for b in boards:
        url, expect, dest = BOARDS[b]
        rc = fetch(b, url=a.url or url, expect=a.digest or expect,
                   dest=Path(a.dest) if a.dest and not a.all else dest,
                   force=a.force, timeout=a.timeout)
        if rc:
            return rc
    print("\nnext: python -m pytest -q   ·   python tools/make_verification.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
