"""Firmware container readers: ELF, Intel HEX, UF2 and headerless dumps.

A firmware "file" is rarely one thing: an OpenMV release is an ELF plus a raw
flash image plus a romfs; an ESP32 image hides behind a 64-byte stub header;
bootloaders ship a UF2 (or DfuSe, which this tool refuses to guess at) wrapper
around the same flash blob.  Everything downstream operates on a flat list of
`Segment`s (a virtual address plus the bytes that live there), so the analysis
never has to care where the bytes came from — and every segment remembers its
provenance for the evidence record.
"""
from __future__ import annotations

import re
import struct
from bisect import bisect_right
from dataclasses import dataclass, field

#: ELF `e_machine` numbers that the published ABI tables settle: 8 MIPS, 20 PowerPC,
#: 40 ARM, 42 SuperH, 62 x86-64, 83 AVR, 183 AArch64, 243 RISC-V.  Unlisted values
#: report `arch: null` and the vector-table shape test decides whether the image is
#: ARM — inventing a family for a number we have not checked is how a tool ends up
#: decoding Xtensa bytes as Thumb.
ELF_MACHINES = {8: "mips", 20: "powerpc", 40: "arm", 42: "superh", 62: "x86-64",
                83: "avr", 183: "aarch64", 243: "riscv"}

CODE_SECTION_RE = re.compile(r"(^\.text|isr_vector|^\.vector|\.rocode|^\.sframework)", re.I)
RODATA_SECTION_RE = re.compile(r"(^\.rodata|\.const|\.text\.ro|^_str|^\.string)", re.I)


@dataclass(slots=True)
class Segment:
    vaddr: int
    data: bytes
    kind: str = "raw"            # text | rodata | data | raw
    name: str | None = None
    source: str = "raw"           # elf.PT_LOAD | elf.section | ihex | uf2 | raw
    file_base: int | None = None  # offset in the file where `data` starts (evidence anchor)
    records: list[tuple[int, int]] = field(default_factory=list, repr=False)
    #       (vaddr, file_offset) of each contributing record, address-ordered.
    #       Textual containers (Intel HEX) need it: their bytes are hex-encoded
    #       inside a line, so `file_base + index` would not be their real home.
    _rec_keys: list[int] = field(default_factory=list, repr=False)

    @property
    def end(self) -> int:
        return self.vaddr + len(self.data)

    def offset_of(self, vaddr: int) -> int | None:
        """Translate a virtual address back to a byte index inside this segment."""
        if self.vaddr <= vaddr < self.end:
            return vaddr - self.vaddr
        return None

    def evidence_offset(self, index: int) -> tuple[int | None, str]:
        """Where the byte at `index` of this segment came from, in the *file*.

        Binary containers map linearly, so the answer is a plain offset.  Intel
        HEX does not: the four bytes a finding quotes are hex digits spread over
        a record line, so the anchor reported is the start of the record holding
        them, and the note says exactly that instead of pretending otherwise.
        """
        if self.file_base is None:
            return None, ""
        if not self.records:
            return self.file_base + index, ""
        if not self._rec_keys:
            self._rec_keys = [r[0] for r in self.records]
        i = bisect_right(self._rec_keys, self.vaddr + index) - 1
        if i < 0:
            return self.file_base, ""
        return self.records[i][1], "; offset is the Intel HEX record holding these bytes"

    def to_dict(self) -> dict:
        return {"vaddr": f"0x{self.vaddr:08X}", "size": len(self.data), "kind": self.kind,
                "name": self.name, "source": self.source}


@dataclass(slots=True)
class Image:
    path: str
    size: int
    fmt: str                      # elf | ihex | uf2 | raw (+ wrapper detections)
    arch: str | None
    endian: str                   # little | big
    entry: int | None
    segments: list[Segment] = field(default_factory=list)
    symbols: dict[int, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    #: the bytes this image was parsed from, when a caller handed them over.
    #: It exists so one file read can serve the hash, the segments and the oracle
    #: instead of three; `to_dict` never serialises it, and `repr=False` keeps a
    #: debugger from printing a megabyte of firmware.
    raw: bytes | None = field(default=None, repr=False)

    def find(self, vaddr: int) -> Segment | None:
        for s in self.segments:
            if s.vaddr <= vaddr < s.end:
                return s
        return None

    def read(self, vaddr: int, n: int) -> bytes | None:
        s = self.find(vaddr)
        if not s:
            return None
        off = s.offset_of(vaddr)
        if off is None or off + n > len(s.data):
            return None
        return s.data[off:off + n]

    def to_dict(self) -> dict:
        return {"path": self.path, "size": self.size, "format": self.fmt, "arch": self.arch,
                "endian": self.endian, "entry": None if self.entry is None else f"0x{self.entry:08X}",
                "segments": [s.to_dict() for s in self.segments],
                "symbol_count": len(self.symbols), "notes": self.notes}


# --------------------------------------------------------------------------- ELF

def load_elf(raw: bytes, path: str) -> Image:
    # Everything below reads the header at fixed offsets, so the length is checked here
    # instead of letting `raw[4]` raise IndexError and `unpack_from` raise struct.error.
    # Neither of those is a ValueError, so neither was caught by the CLI's usage-error
    # handler: a four-byte file that began `\x7fELF` used to end a scan with a traceback
    # instead of with a sentence about what is missing.
    if len(raw) < 16:
        raise ValueError(f"truncated ELF: {len(raw)} byte(s), the identification block "
                         f"alone needs 16")
    is64 = raw[4] == 2
    endian = "little" if raw[5] == 1 else "big"
    p = "<" if endian == "little" else ">"
    # The widest field read below is `e_shentsize/e_shnum/e_shstrndx`: three halfwords at
    # offset 58 for ELF64 (so 64 bytes) and at 46 for ELF32 (so 52).
    need = 64 if is64 else 52
    if len(raw) < need:
        raise ValueError(f"truncated ELF{64 if is64 else 32} header: {len(raw)} byte(s) "
                         f"in the file, the fields this tool reads need {need}")
    # Elf32_Ehdr: ident16 type18 machine... version20 entry24 phoff28 shoff32
    #              flags36 ehsize40 phentsize42 phnum44 shentsize46 shnum48 shstrndx50
    # Elf64_Ehdr: ... flags48(half at 52) ehsize52 phentsize54 phnum56 shentsize58
    if is64:
        e_machine = struct.unpack_from(p + "H", raw, 18)[0]
        e_entry = struct.unpack_from(p + "Q", raw, 24)[0]
        e_phoff, e_shoff = struct.unpack_from(p + "QQ", raw, 32)
        e_phentsize, e_phnum = struct.unpack_from(p + "HH", raw, 54)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(p + "HHH", raw, 58)
    else:
        e_machine = struct.unpack_from(p + "H", raw, 18)[0]
        e_entry = struct.unpack_from(p + "I", raw, 24)[0]
        e_phoff, e_shoff = struct.unpack_from(p + "II", raw, 28)
        e_phentsize, e_phnum = struct.unpack_from(p + "HH", raw, 42)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(p + "HHH", raw, 46)

    arch = ELF_MACHINES.get(e_machine)

    segments: list[Segment] = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if o + (32 if is64 else 24) > len(raw):
            break
        if is64:
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from(
                p + "IIQQQQ", raw, o)[0:7]
        else:
            p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags = struct.unpack_from(
                p + "IIIIIII", raw, o)[:7]
        if p_type != 1 or p_filesz == 0:      # PT_LOAD
            continue
        if p_offset + p_filesz > len(raw):
            segments.append(Segment(p_vaddr, raw[p_offset:], "raw", None,
                                    "elf.PT_LOAD(truncated)", p_offset))
            continue
        kind = "text" if p_flags & 1 else ("data" if p_flags & 2 else "rodata")
        segments.append(Segment(p_vaddr, raw[p_offset:p_offset + p_filesz], kind, None,
                                "elf.PT_LOAD", p_offset))

    # section headers: refine PT_LOAD naming, and supply segments when no PT_LOAD
    # was usable.  Adding a segment per section as well would double-count every
    # carved constant, so sections only *annotate* loaded bytes here.
    names: dict[int, str] = {}
    sections: list[tuple[int, int, int, str]] = []      # (addr, off, size, name)
    if e_shstrndx < e_shnum and e_shentsize:
        so = e_shoff + e_shstrndx * e_shentsize
        shstr_off = struct.unpack_from(p + ("Q" if is64 else "I"), raw,
                                       so + (24 if is64 else 16))[0]
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            if o + e_shentsize > len(raw):
                break
            nm_off = struct.unpack_from(p + "I", raw, o)[0]
            se = raw.find(b"\0", shstr_off + nm_off)
            nm = raw[shstr_off + nm_off:se].decode("utf8", "replace") if nm_off else ""
            names[i] = nm
            addr = struct.unpack_from(p + ("Q" if is64 else "I"), raw, o + (16 if is64 else 12))[0]
            off = struct.unpack_from(p + ("Q" if is64 else "I"), raw, o + (24 if is64 else 16))[0]
            size = struct.unpack_from(p + ("Q" if is64 else "I"), raw, o + (32 if is64 else 20))[0]
            if nm and size and off and off + size <= len(raw) and addr:
                # sh_addr == 0 means the section is not part of the memory image
                # (.debug_*, .ARM.attributes, comment): metadata, not bytes the CPU
                # can see.  Loading them as segments would corrupt every address
                # range the analysis reasons about.
                sections.append((addr, off, size, nm))

    for seg in segments:
        hit = [s for s in sections if s[0] == seg.vaddr and s[2] <= len(seg.data) + 8]
        if hit:
            best = max(hit, key=lambda s: s[2])
            seg.name, seg.kind = best[3], _kind_for(best[3], seg.kind)
    covered = {(s.vaddr, len(s.data)) for s in segments}
    for addr, off, size, nm in sections:
        if any(v == addr and size <= ln for v, ln in covered):
            continue
        segments.append(Segment(addr, raw[off:off + size], _kind_for(nm, "raw"), nm,
                                "elf.section", off))

    symbols: dict[int, str] = {}
    for i, nm in list(names.items()):
        if nm != ".symtab":
            continue
        o = e_shoff + i * e_shentsize
        try:
            sh_link = struct.unpack_from(p + "I", raw, o + (40 if is64 else 24))[0]
            off = struct.unpack_from(p + ("Q" if is64 else "I"), raw, o + (24 if is64 else 16))[0]
            size = struct.unpack_from(p + ("Q" if is64 else "I"), raw, o + (32 if is64 else 20))[0]
            entsize = struct.unpack_from(p + ("Q" if is64 else "I"), raw, o + (56 if is64 else 36))[0]
            strtab_off = struct.unpack_from(
                p + ("Q" if is64 else "I"), raw,
                e_shoff + sh_link * e_shentsize + (24 if is64 else 16))[0]
            if not entsize:
                continue
            for k in range(size // entsize):
                eo = off + k * entsize
                st_name = struct.unpack_from(p + "I", raw, eo)[0]
                st_value = struct.unpack_from(p + ("Q" if is64 else "I"), raw, eo + (8 if is64 else 4))[0]
                st_info = raw[eo + (4 if is64 else 12)]
                if not st_value or not st_name or (st_info & 0xF) != 2:   # STT_FUNC only
                    continue
                se = raw.find(b"\0", strtab_off + st_name)
                symbols[st_value & ~1] = raw[strtab_off + st_name:se].decode("utf8", "replace")
        except (struct.error, IndexError):
            continue

    segments.sort(key=lambda s: s.vaddr)
    return Image(path, len(raw), "elf", arch, endian, e_entry, segments, symbols)


def _kind_for(section_name: str, default: str) -> str:
    if CODE_SECTION_RE.search(section_name):
        return "text"
    if RODATA_SECTION_RE.search(section_name):
        return "rodata"
    if section_name.startswith((".isr", ".vector")):
        return "text"
    return default


# ---------------------------------------------------------------------- Intel HEX

def load_ihex(text: bytes, path: str) -> Image | None:
    base = 0
    chunks: dict[int, tuple[bytes, int | None]] = {}
    pos = 0
    for raw_line in text.splitlines(keepends=True):
        line = raw_line.strip()
        here = pos
        pos += len(raw_line)                     # exact byte offset of this ':' line
        if not line.startswith(b":") and not isinstance(line, bytes):
            continue
        if isinstance(line, str):
            line = line.encode()
        if not re.fullmatch(rb":[0-9A-Fa-f]+", line):
            continue
        try:
            rec = bytes.fromhex(line[1:].decode())
        except ValueError:
            continue
        if len(rec) < 5 or (sum(rec) & 0xFF) != 0:
            return None
        count, addr, rtype = rec[0], rec[1] << 8 | rec[2], rec[3]
        if len(rec) - 5 != count:                 # the length byte must match the record
            return None
        data = rec[4:4 + count]
        if rtype == 0:
            # The line's own byte offset is the evidence anchor.  The earlier version
            # re-searched the text from a cursor, and a repeated 16-byte record (very
            # common: runs of 0x00 and 0xFF) resolved to the *first* copy, so every
            # later one quoted an offset whose bytes did not match its own payload.
            chunks[base + addr] = (data, here)
        elif rtype == 1:
            break
        elif rtype in (2, 4):
            if len(data) < 2:
                return None
            base = (data[0] << 8 | data[1]) << (4 if rtype == 2 else 16)
        elif rtype == 5:
            pass
    if not chunks:
        return None
    segments = _merge(chunks, "ihex")
    img = Image(path, len(text), "ihex", None, "little", None, segments)
    _claim_arch_from_table(img, segments, "Intel HEX")
    return img


def _claim_arch_from_table(img: Image, segments: list[Segment], whence: str) -> None:
    """Say "arm" only when a Cortex-M vector table validates inside the image.

    Neither Intel HEX nor UF2 carries a machine field, and the extension proves
    nothing about the core.  "First word is a RAM pointer and the next dozen are
    odd targets inside this image" is a shape only ARM produces, so the claim is
    earned from the bytes with the same scanner the rest of the pipeline uses —
    and stays unsaid when the table is absent.
    """
    from .vectors import scan_tables  # deferred: vectors imports this module

    first = segments[0] if segments else None
    if not first or len(first.data) < 8 * 4:
        return
    probe = Image("<probe>", len(first.data), img.fmt, None, "little", None, segments)
    if scan_tables(probe):
        img.arch = "arm"
        img.notes.append(f"arch set to arm: a Cortex-M vector table validates inside "
                         f"this {whence} image")


# --------------------------------------------------------------------------- UF2

#: layout as published at https://microsoft.github.io/uf2/ (512-byte blocks:
#: 32-byte header, 476 bytes of data, trailing magic).  Every offset below is
#: asserted by tests/test_container.py against these constants, because a reader
#: that is 4 bytes off still "finds blocks" and returns garbage payloads.
UF2_BLOCK_SIZE = 512
UF2_MAGIC0 = 0x0A324655            # offset 0,  "UF2\n"
UF2_MAGIC1 = 0x9E5D5157            # offset 4
UF2_MAGIC_END = 0x0AB16F30         # offset 508
UF2_OFF_FLAGS = 8
UF2_OFF_TARGET_ADDR = 12
UF2_OFF_PAYLOAD_SIZE = 16
UF2_OFF_BLOCK_NO = 20
UF2_OFF_NUM_BLOCKS = 24
UF2_OFF_FILE_SIZE_OR_FAMILY = 28
UF2_OFF_DATA = 32
UF2_FLAG_NOT_MAIN_FLASH = 0x00000001
UF2_FLAG_FILE_CONTAINER = 0x00001000
UF2_FLAG_FAMILY_ID = 0x00002000


def load_uf2(raw: bytes, path: str) -> Image | None:
    if len(raw) < UF2_BLOCK_SIZE:
        return None
    blocks: list[tuple[int, tuple[bytes, int]]] = []
    family = None
    skipped = 0
    for i in range(0, len(raw) - (UF2_BLOCK_SIZE - 1), UF2_BLOCK_SIZE):
        b = raw[i:i + UF2_BLOCK_SIZE]
        if len(b) < UF2_BLOCK_SIZE:
            break
        if (struct.unpack_from("<I", b, 0)[0] != UF2_MAGIC0
                or struct.unpack_from("<I", b, 4)[0] != UF2_MAGIC1
                or struct.unpack_from("<I", b, UF2_BLOCK_SIZE - 4)[0] != UF2_MAGIC_END):
            continue
        flags = struct.unpack_from("<I", b, UF2_OFF_FLAGS)[0]
        target_addr = struct.unpack_from("<I", b, UF2_OFF_TARGET_ADDR)[0]
        payload_size = struct.unpack_from("<I", b, UF2_OFF_PAYLOAD_SIZE)[0]
        if flags & UF2_FLAG_FAMILY_ID:
            family = struct.unpack_from("<I", b, UF2_OFF_FILE_SIZE_OR_FAMILY)[0]
        if flags & UF2_FLAG_NOT_MAIN_FLASH:      # comment/debug blocks, not firmware
            skipped += 1
            continue
        if flags & UF2_FLAG_FILE_CONTAINER:      # wraps other files, e.g. a .bin
            skipped += 1
            continue
        payload = b[UF2_OFF_DATA:UF2_OFF_DATA + max(0, min(payload_size,
                                                            UF2_BLOCK_SIZE - UF2_OFF_DATA))]
        if not payload:
            continue
        blocks.append((target_addr, (payload, i)))
    if not blocks:
        return None
    chunks = dict(blocks)
    segments = _merge(chunks, "uf2")
    notes = [f"UF2 blocks: {len(blocks)} data, {skipped} skipped "
             f"(not-main-flash or file-container flag)",
             f"family id: 0x{family:08X}" if family is not None else
             "family id: absent (bit 0x2000 clear; board name not claimed)"]
    img = Image(path, len(raw), "uf2", None, "little", None, segments, notes=notes)
    _claim_arch_from_table(img, segments, "UF2")
    return img


# ------------------------------------------------------------------------ DfuSe

#: ST's DfuSe wrapper.  Detected and refused, not guessed.
DFUSE_SIGNATURE = b"DfuSe"


def is_dfuse(raw: bytes) -> bool:
    return raw[:5] == DFUSE_SIGNATURE and raw[7:14].startswith(b"DfuTarg")


# --------------------------------------------------------------------- raw dumps

#: where Cortex-M / RISC-V images are usually flashed; used only when a raw dump
#: carries no container header at all.
COMMON_FLASH_BASES = (0x08000000, 0x08010000, 0x00000000, 0x00100000, 0x02000000,
                      0x10000000, 0x10010000, 0x30000000, 0x30040000, 0x90000000,
                      0x1C000000, 0x0C000000)

#: Windows a Cortex-M initial stack pointer can live in, taken per vendor RAM alias
#: rather than as one big "looks like memory" band.  The earlier range
#: (0x1000_0000-0x4FFF_FFFF) admitted the whole peripheral space, so a .rodata word
#: like 0x3958_4A1D passed as a stack pointer and the scanner "found" a table in noise.
#: The bottom 1 MB is deliberately *not* a window: ITCM is only 64 KB on the parts that
#: have it, and a wide low band is what turns the small integers in a constant pool
#: (lengths, versions, sizes) into plausible stack pointers.
SP_WINDOWS = ((0x0000_0000, 0x0000_FFFF),       # Cortex-M7 ITCM (STM32H7 boots there)
              (0x1000_0000, 0x1FFF_FFFF),       # STM32 CCM / RP2040 SRAM
              (0x2000_0000, 0x2FFF_FFFF),       # the SRAM/DTCM/AXI-SRAM alias
              (0x3000_0000, 0x3FFF_FFFF))       # STM32H7 D2/D3 SRAM, nRF91


def guess_load_base(data: bytes) -> tuple[int, int, int, dict[int, int]]:
    """Return (tables_at_best, base, first_table_file_offset, per_base_table_counts).

    The shape test itself lives in `vectors.py` - one implementation, no drift
    between "where is the table" and "what address does the table imply".  The whole
    count map comes back, not just the runners-up: a dump reader has to be able to see
    which origins were tested and rejected, not only that something was chosen.  The
    import is deferred because vectors imports this module.
    """
    from .vectors import infer_load_base  # deferred: breaks the import cycle

    base, n_tables, first_off, counts = infer_load_base(data)
    if not n_tables:                             # 0x00000000 is a real base (nRF52)
        return 0, 0, 0, counts
    return n_tables, base, first_off, counts


def load_raw(data: bytes, path: str, base: int | None = None) -> Image:
    score, guessed, table_off, counts = \
        (0, 0, 0, {}) if base is not None else guess_load_base(data)
    chosen = base if base is not None else (guessed or 0)
    notes = []
    if base is None and not score:
        # Nothing earned this address.  The sentence used to read like the reasoned one --
        # "inferred as 0x00000000: of the 12 origins tested it is the one whose best
        # candidate reads most like a vector table (0 table(s) there)" -- which dresses a
        # null result up as a choice and invites a reader to trust an address the image
        # never supported.
        notes.append(
            f"raw dump: no container header, and no vector table at any of the "
            f"{len(counts) or 1} origins tested. load base shown as 0x{chosen:08X} because "
            f"a scan needs one, not because this image supports it -- the address carries "
            f"no evidence. Pass --base to pin it, or treat this file as not a Cortex-M image.")
    elif base is None:
        rivals = sorted((b, n) for b, n in counts.items() if b != chosen and n)
        notes.append(
            f"raw dump: no container header. load base inferred as 0x{chosen:08X}: "
            f"of the {len(counts)} origins tested it is the one whose best candidate "
            f"reads most like a vector table ({score} table(s) there, the first at "
            f"file offset 0x{table_off:X})"
            + ("; origins that also produced tables: "
               + ", ".join(f"0x{b:08X}({n})" for b, n in rivals) if rivals
               else "; every other tested origin produced no table")
            + ". Pass --base to pin it.")
        if score > 1:
            notes.append("more than one vector table: this is probably a merged image "
                         "(bootloader + application) or a dump that contains a RAM copy "
                         "of the table; the scan reports each one separately")
    is_code = _looks_cortex_m(data, chosen) or bool(score)
    seg = Segment(chosen, data, "text" if is_code else "raw", None, "raw", 0)
    arch = "arm" if is_code else None
    return Image(path, len(data), "raw", arch, "little", None, [seg], notes=notes)


def _looks_cortex_m(data: bytes, base: int) -> bool:
    if len(data) < 8:
        return False
    sp = struct.unpack_from("<I", data, 0)[0]
    reset = struct.unpack_from("<I", data, 4)[0]
    return bool(reset & 1) and base <= (reset & ~1) < base + max(len(data), 0x10_0000) \
        and any(lo <= sp <= hi for lo, hi in SP_WINDOWS)


def _merge(chunks: dict[int, tuple], source: str) -> list[Segment]:
    """Fold sparse record chunks into contiguous segments, tolerating holes.

    `file_base` survives because records arrive address-ordered and holes are
    filled with 0xFF (erased flash), which keeps the virtual/file distance
    linear enough for the reader to report a re-checkable offset.  Each record's
    own (vaddr, file offset) pair is kept in `Segment.records` so a textual
    container can still point a finding at the line its bytes came from.
    """
    out: list[Segment] = []
    for addr in sorted(chunks):
        payload = chunks[addr]
        data, file_off = (payload, None) if isinstance(payload, bytes) else payload
        if out and out[-1].end + 8 >= addr and addr >= out[-1].vaddr:
            prev = out[-1]
            gap = addr - prev.end
            pad = b"\xff" * max(gap, 0)
            prev.data += pad + bytes(data)
            if file_off is not None:
                prev.records.append((addr, file_off))
        else:
            seg = Segment(addr, bytes(data), "raw", None, source, file_off)
            if file_off is not None:
                seg.records.append((addr, file_off))
            out.append(seg)
    for s in out:
        if s.vaddr < 0x1000_0000:
            s.kind = "text"
        elif 0x1000_0000 <= s.vaddr < 0x4000_0000:
            s.kind = "data"
    return out


# ------------------------------------------------------------------------ entry

def load(path: str, base: int | None = None, arch: str | None = None) -> Image:
    """Open any supported container.  Falls through wrappers before giving up."""
    with open(path, "rb") as fh:
        return load_bytes(fh.read(), path, base=base, arch=arch)


def load_bytes(raw: bytes, path: str, base: int | None = None,
               arch: str | None = None) -> Image:
    """Open a container from bytes already in hand.

    Split out of `load()` because the pipeline needs the same bytes three times
    (the sha256, the segments, the symbol oracle) and reading a several-megabyte
    firmware per use was both slow and a consistency hazard: a file rewritten
    between reads produced a report whose hash did not describe its own findings.
    The image keeps the buffer it came from so downstream stages can reuse it.
    """
    notes: list[str] = []
    if raw[:4] == b"\x7fELF":
        img = load_elf(raw, path)
    elif is_dfuse(raw):
        notes.append("DfuSe wrapper detected. Unwrapping it is not implemented, because a "
                     "guessed element offset would put every address in this report in the "
                     "wrong place; extract the image first (dfuse-util -a 0 -s 0x08000000:leave "
                     "or python -m dfu ...), then scan the .bin. The bytes below are analysed "
                     "as a raw dump, which still identifies the part but not the element split.")
        img = _raw_or_fail(raw, path, base)
    elif len(raw) >= UF2_BLOCK_SIZE and \
            struct.unpack_from("<I", raw, 0)[0] == UF2_MAGIC0:
        img = load_uf2(raw, path) or _raw_or_fail(raw, path, base)
        if img.fmt != "uf2":
            img.notes.append("UF2 magic present but no valid 512-byte block parsed; "
                             "analysed as a raw dump")
    elif raw[:1] == b":" and _ihex_probable(raw):
        img = load_ihex(raw, path) or _raw_or_fail(raw, path, base)
        if img.fmt != "ihex":
            img.notes.append("Intel HEX-shaped file with a bad record (checksum or length); "
                             "analysed as a raw dump — the bytes are all still there")
    elif raw[:4] == b"\xed\xa0\xed\x00" or raw[:2] == b"\x1f\x8b":
        raise ValueError(f"{path}: compressed/OTA wrapper — decompress first (firmprint does not guess)")
    else:
        # ESP32 flat-image stub: 0xE9 magic + short header, image body at 0x19-ish
        if raw[:1] == b"\xe9" and len(raw) > 24:
            notes.append("ESP32 stub header (0xE9) detected but not unwrapped; "
                         "run esptool image_dump first for accurate segment split")
        img = _raw_or_fail(raw, path, base)
    img.notes.extend(notes)
    if arch:
        img.arch = arch
    if not img.segments:
        raise ValueError(f"{path}: no loadable segments found")
    img.segments.sort(key=lambda s: s.vaddr)
    img.raw = raw
    return img


def _raw_or_fail(raw: bytes, path: str, base: int | None) -> Image:
    return load_raw(raw, path, base)


def _ihex_probable(raw: bytes) -> bool:
    lines = raw[:4096].splitlines()
    good = sum(1 for ln in lines if re.fullmatch(rb":[0-9A-Fa-f]{8,}", ln))
    return bool(lines) and good >= max(2, len(lines) * 3 // 4)
