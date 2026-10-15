"""Container readers: ELF, Intel HEX, UF2, DfuSe and headerless dumps.

Every synthetic file here is built to a published layout, not to whatever the
reader happens to accept — `uf2` in particular is a format whose field offsets
were misread by an earlier version of this file, and a self-consistent test
would have blessed the mistake forever.
"""
from __future__ import annotations

import struct

import pytest
from conftest import cortex_m_image, dfuse_stub, ihex, uf2

from firmprint import container
from firmprint.container import Image, Segment, load, load_raw

# https://microsoft.github.io/uf2/ — 512-byte blocks
UF2_MAGIC0, UF2_MAGIC1, UF2_MAGIC_END = 0x0A324655, 0x9E5D5157, 0x0AB16F30


# ------------------------------------------------------------------------ ELF

@pytest.mark.sample
def test_elf_gives_segments_symbols_and_a_thumb_entry(elf_path):
    img = load(str(elf_path))
    assert img.fmt == "elf"
    assert img.arch == "arm"
    assert img.endian == "little"
    assert img.entry is not None and img.entry & 1, "Cortex-M entries are Thumb"
    assert img.symbols, "the symbol table is what seeds the decoder"
    assert len(img.symbols) > 1000
    assert any(s.name for s in img.segments), "section headers should name segments"
    assert any(s.file_base is not None for s in img.segments)


@pytest.mark.sample
def test_elf_addresses_round_trip_to_file_bytes(elf_path):
    """The evidence contract only means something if vaddr -> file offset works."""
    img = load(str(elf_path))
    raw = elf_path.read_bytes()
    checked = 0
    for seg in img.segments:
        if seg.file_base is None or len(seg.data) < 8:
            continue
        for index in (0, len(seg.data) // 2, len(seg.data) - 4):
            anchor, whence = seg.evidence_offset(index)
            assert anchor is not None and whence == "", "binary container maps linearly"
            assert raw[anchor:anchor + 4] == seg.data[index:index + 4], \
                f"{seg.source}: file offset {anchor} does not hold the quoted bytes"
            checked += 1
    assert checked > 10


@pytest.mark.sample
def test_debug_sections_are_not_loaded_as_memory(elf_path):
    """A .debug_* section has sh_addr 0: it is metadata, not something the CPU sees."""
    img = load(str(elf_path))
    assert all(s.vaddr for s in img.segments)
    for seg in img.segments:
        if seg.name:
            assert not seg.name.startswith(".debug"), f"{seg.name} is not a memory image"


# -------------------------------------------------------------------- Intel HEX

def test_ihex_records_fold_into_one_segment_and_keep_their_line(tmp_path):
    body = cortex_m_image(base=0x0800_0000, code_bytes=0x100)
    text = ihex([(0x0800_0000, body)])
    p = tmp_path / "app.hex"
    p.write_bytes(text)
    img = load(str(p))
    assert img.fmt == "ihex"
    assert img.arch == "arm", "a hex file has no machine field; the table says ARM"
    assert len(img.segments) == 1
    seg = img.segments[0]
    assert seg.vaddr == 0x0800_0000
    assert seg.data[:8] == body[:8]
    assert seg.records, "each record's file position must survive merging"


def test_ihex_evidence_offset_points_at_a_real_record(tmp_path):
    """For a textual container the honest anchor is the record, not a fake linear offset."""
    body = cortex_m_image(base=0x0800_0000, code_bytes=0x100)
    text = ihex([(0x0800_0000, body)])
    p = tmp_path / "app.hex"
    p.write_bytes(text)
    img = load(str(p))
    seg = img.segments[0]
    anchor, whence = seg.evidence_offset(0)
    line = text[anchor:].split(b"\n")[0]
    assert line.startswith(b":"), f"offset {anchor} is not a record start: {line[:20]!r}"
    assert "Intel HEX record" in whence
    # the record named must be the one whose payload begins with the quoted bytes
    payload = bytes.fromhex(line[9:9 + 2 * int(line[1:3], 16)].decode())
    assert payload[:4] == seg.data[:4]
    assert line[:9].decode().upper() == f":{len(payload):02X}000000", "record 0 at the base"


def test_ihex_repeated_records_do_not_all_claim_the_first_line():
    """The old cursor search re-resolved duplicate records to the earliest copy."""
    body = b"\xAA" * 32 + b"\xFF" * 32 + b"\xAA" * 32
    text = ihex([(0x0800_0000, body)])
    img = container.load_ihex(text, "<memory>")
    assert img is not None
    seg = img.segments[0]
    assert len({off for _v, off in seg.records}) == len(seg.records)
    for vaddr, off in seg.records:                    # every anchor must quote its own line
        line = text[off:].split(b"\n")[0]
        count = int(line[1:3], 16)
        payload = bytes.fromhex(line[9:9 + 2 * count].decode())
        index = vaddr - seg.vaddr
        assert seg.data[index:index + len(payload)] == payload, hex(vaddr)


def test_a_bad_checksum_falls_back_to_raw_and_says_so(tmp_path):
    body = cortex_m_image(base=0x0800_0000, code_bytes=0x40)
    text = ihex([(0x0800_0000, body)])
    lines = text.splitlines()
    broken = lines[2][:-2] + b"00"            # corrupt the trailing checksum
    data = b"\n".join(lines[:2] + [broken] + lines[3:]) + b"\n"
    p = tmp_path / "broken.hex"
    p.write_bytes(data)
    img = load(str(p))
    assert img.fmt == "raw", "a hex file that fails record validation is not a hex file"
    assert any("Intel HEX" in n for n in img.notes), img.notes
    assert img.segments[0].data == data, "refusing the wrapper must not drop a byte"


# ---------------------------------------------------------------------------- UF2

def test_uf2_block_layout_follows_the_published_spec():
    payload = bytes(range(64))
    blob = uf2(0x0800_0000, payload, family=0x68B1D9CA)
    b = blob[:512]
    assert struct.unpack_from("<I", b, 0)[0] == UF2_MAGIC0
    assert struct.unpack_from("<I", b, 4)[0] == UF2_MAGIC1
    assert struct.unpack_from("<I", b, 8)[0] & 0x2000, "family-present flag"
    assert struct.unpack_from("<I", b, 12)[0] == 0x0800_0000     # targetAddr
    assert struct.unpack_from("<I", b, 16)[0] == 64              # numBytes
    assert struct.unpack_from("<I", b, 20)[0] == 0               # blockNo
    assert struct.unpack_from("<I", b, 24)[0] == 1               # numBlocks
    assert struct.unpack_from("<I", b, 28)[0] == 0x68B1D9CA      # familyID
    assert struct.unpack_from("<I", b, 508)[0] == UF2_MAGIC_END
    assert len(blob) == 512


def test_uf2_payload_and_family_survive_parsing(tmp_path):
    payload = cortex_m_image(base=0x0800_0000, code_bytes=0x200)
    p = tmp_path / "app.uf2"
    p.write_bytes(uf2(0x0800_0000, payload, family=0x68B1D9CA))
    img = load(str(p))
    assert img.fmt == "uf2"
    assert img.arch == "arm"
    assert img.segments[0].data == payload
    assert any("0x68B1D9CA" in n for n in img.notes), img.notes
    assert any("family id" in n.lower() for n in img.notes)


def test_uf2_comment_blocks_are_skipped_not_flashed(tmp_path):
    """Flag 0x00000001 means "not main flash": the block must not become a segment."""
    good = uf2(0x0800_0000, cortex_m_image(base=0x0800_0000, code_bytes=0x40))
    note = uf2(0x080F_0000, b"Micropython source comment" * 2, flags=0x00000001)
    p = tmp_path / "withcomment.uf2"
    p.write_bytes(good + note)
    img = load(str(p))
    assert img.fmt == "uf2"
    assert [s.vaddr for s in img.segments] == [0x0800_0000]
    assert any("1 skipped" in n for n in img.notes), img.notes


def test_uf2_without_the_family_flag_does_not_claim_a_board(tmp_path):
    p = tmp_path / "nofamily.uf2"
    p.write_bytes(uf2(0x0800_0000, cortex_m_image(base=0x0800_0000, code_bytes=0x40)))
    img = load(str(p))
    assert any("absent" in n for n in img.notes), img.notes


def test_uf2_magic_that_is_not_a_block_falls_back_to_raw(tmp_path):
    """A file that opens with the magic but whose 512-byte block fails validation must
    still be analysed — and must say which of the two stories it is telling."""
    p = tmp_path / "broken.uf2"
    p.write_bytes(struct.pack("<I", UF2_MAGIC0) + b"\x00" * 600)
    img = load(str(p))
    assert img.fmt == "raw"
    assert any("UF2" in n for n in img.notes), img.notes


# ----------------------------------------------------------------------- DfuSe

def test_dfuse_is_detected_and_refused(tmp_path):
    """A wrapper we cannot verify is not a reason to invent element addresses.

    DfuSe puts each element at a `u32ElementAddress` inside a nested
    target/image/element chain.  The offsets of that chain are the kind of thing
    a reader gets four bytes wrong without any test noticing, and a wrong element
    address means every finding in the report is labelled with the wrong place.
    So the container says what it found, tells the user how to unwrap it, and
    analyses the bytes as a raw dump — which still identifies the part.
    """
    body = cortex_m_image(base=0x0800_0000, code_bytes=0x100)
    blob = dfuse_stub(body)
    p = tmp_path / "app.dfu"
    p.write_bytes(blob)
    assert container.is_dfuse(blob)
    img = load(str(p))
    assert img.fmt == "raw"
    assert any("DfuSe" in n and "not implemented" in n for n in img.notes), img.notes
    assert img.segments[0].data[-len(body):] == body, "no flash byte is lost in the refusal"


# ------------------------------------------------------------------ raw dumps

def test_raw_dump_infers_a_base_and_reports_the_alternatives():
    data = cortex_m_image(base=0x0801_0000)
    img = load_raw(data, "app.bin")
    assert img.fmt == "raw"
    assert img.segments[0].vaddr == 0x0801_0000
    assert any("inferred" in n for n in img.notes)
    assert any("--base" in n for n in img.notes), "the ambiguity must be printed, not hidden"


def test_raw_dump_pin_the_base_skips_the_inference():
    data = cortex_m_image(base=0x0800_0000)
    img = load_raw(data, "app.bin", base=0x0800_0000)
    assert img.segments[0].vaddr == 0x0800_0000
    assert not img.notes, "an explicit base leaves nothing to explain"


def test_esp32_stub_is_announced_not_silently_flattened(tmp_path):
    data = b"\xe9" + bytes(40) + cortex_m_image(base=0x4000_0000, code_bytes=0x40)
    p = tmp_path / "esp.bin"
    p.write_bytes(data)
    img = load(str(p))
    assert img.fmt == "raw"
    assert any("ESP32" in n for n in img.notes), img.notes


def test_gzip_is_refused_with_an_instruction_not_a_guess(tmp_path):
    p = tmp_path / "ota.bin.gz"
    p.write_bytes(b"\x1f\x8b\x08\x00" + bytes(200))
    with pytest.raises(ValueError, match="decompress first"):
        load(str(p))


def test_image_read_translates_addresses_and_respects_bounds():
    seg = Segment(0x0800_0000, bytes(range(64)), "text", ".text", "raw", 0)
    img = Image("m", 64, "raw", "arm", "little", None, [seg])
    assert img.read(0x0800_0000, 4) == b"\x00\x01\x02\x03"
    assert img.read(0x0800_0030, 8) == bytes(range(0x30, 0x38))
    assert img.read(0x0800_0040, 1) is None, "past the end must be None, not a wrap"
    assert img.read(0x0800_003E, 8) is None, "a straddling read must not silently clip"
    assert img.find(0x0800_0010) is seg
    assert img.find(0x0801_0000) is None
