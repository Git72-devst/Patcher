from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


PE32PLUS_MAGIC = 0x20B
SECTION_HEADER_SIZE = 40
IL_SECTION_CHARACTERISTICS = 0x60000020


def rd_u16(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def rd_u32(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def wr_u16(data: bytearray, off: int, value: int) -> None:
    struct.pack_into("<H", data, off, value)


def wr_u32(data: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", data, off, value)


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


@dataclass
class Section:
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int


class PeImage:
    def __init__(self, data: bytes) -> None:
        self.data = bytearray(data)
        if len(self.data) <= 0x40 or self.data[:2] != b"MZ":
            raise ValueError("not a PE file")
        pe_offset = rd_u32(self.data, 0x3C)
        if self.data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        self.coff_offset = pe_offset + 4
        self.opt_offset = self.coff_offset + 20
        magic = rd_u16(self.data, self.opt_offset)
        if magic != PE32PLUS_MAGIC:
            raise ValueError(f"only PE32+ is supported, magic=0x{magic:X}")
        self.num_sections = rd_u16(self.data, self.coff_offset + 2)
        size_of_optional = rd_u16(self.data, self.coff_offset + 16)
        self.section_table_offset = self.opt_offset + size_of_optional

    def opt_u32(self, field: int) -> int:
        return rd_u32(self.data, self.opt_offset + field)

    def set_opt_u32(self, field: int, value: int) -> None:
        wr_u32(self.data, self.opt_offset + field, value)

    @property
    def section_alignment(self) -> int:
        return self.opt_u32(32)

    @property
    def file_alignment(self) -> int:
        return self.opt_u32(36)

    @property
    def size_of_headers(self) -> int:
        return self.opt_u32(60)

    def section(self, index: int) -> Section:
        off = self.section_table_offset + index * SECTION_HEADER_SIZE
        return Section(
            virtual_size=rd_u32(self.data, off + 8),
            virtual_address=rd_u32(self.data, off + 12),
            raw_size=rd_u32(self.data, off + 16),
            raw_pointer=rd_u32(self.data, off + 20),
        )

    def sections(self) -> list[Section]:
        return [self.section(i) for i in range(self.num_sections)]

    def rva_to_offset(self, rva: int) -> int | None:
        for section in self.sections():
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                return section.raw_pointer + (rva - section.virtual_address)
        return None

    def data_directory(self, index: int) -> tuple[int, int]:
        off = self.opt_offset + 112 + index * 8
        return rd_u32(self.data, off), rd_u32(self.data, off + 4)

    def set_data_directory(self, index: int, rva: int, size: int) -> None:
        off = self.opt_offset + 112 + index * 8
        wr_u32(self.data, off, rva)
        wr_u32(self.data, off + 4, size)

    def metadata_root_offset(self) -> int:
        clr_rva, clr_size = self.data_directory(14)
        if clr_rva == 0 or clr_size < 0x48:
            raise ValueError("not a .NET assembly")
        cli = self.rva_to_offset(clr_rva)
        if cli is None:
            raise ValueError("CLR RVA cannot be mapped")
        meta_rva = rd_u32(self.data, cli + 8)
        meta = self.rva_to_offset(meta_rva)
        if meta is None or self.data[meta : meta + 4] != b"BSJB":
            raise ValueError("metadata root is missing")
        return meta

    def append_section(self, name: str, payload: bytes, characteristics: int) -> int:
        file_align = self.file_alignment
        section_align = self.section_alignment
        new_header_end = self.section_table_offset + (self.num_sections + 1) * SECTION_HEADER_SIZE
        if new_header_end > self.size_of_headers:
            raise ValueError("no room for a new section header")

        security_off, security_size = self.data_directory(4)
        if security_off and security_size:
            cert_end = security_off + security_size
            if cert_end == len(self.data):
                del self.data[security_off:]
            self.set_data_directory(4, 0, 0)

        max_rva_end = 0
        for section in self.sections():
            max_rva_end = max(max_rva_end, section.virtual_address + max(section.virtual_size, section.raw_size))

        new_va = align_up(max_rva_end, section_align)
        raw_ptr = align_up(len(self.data), file_align)
        raw_size = align_up(len(payload), file_align)
        virtual_size = len(payload)

        self.data.extend(b"\0" * (raw_ptr - len(self.data)))
        self.data.extend(payload)
        self.data.extend(b"\0" * (raw_ptr + raw_size - len(self.data)))

        header = self.section_table_offset + self.num_sections * SECTION_HEADER_SIZE
        encoded_name = name.encode("ascii")[:8]
        self.data[header : header + 8] = encoded_name + b"\0" * (8 - len(encoded_name))
        wr_u32(self.data, header + 8, virtual_size)
        wr_u32(self.data, header + 12, new_va)
        wr_u32(self.data, header + 16, raw_size)
        wr_u32(self.data, header + 20, raw_ptr)
        self.data[header + 24 : header + 36] = b"\0" * 12
        wr_u32(self.data, header + 36, characteristics)

        self.num_sections += 1
        wr_u16(self.data, self.coff_offset + 2, self.num_sections)
        self.set_opt_u32(56, align_up(new_va + virtual_size, section_align))
        self.update_checksum()
        return new_va

    def update_checksum(self) -> None:
        checksum_field = self.opt_offset + 64
        self.data[checksum_field : checksum_field + 4] = b"\0\0\0\0"
        total = 0
        length = len(self.data)
        i = 0
        while i + 1 < length:
            total += rd_u16(self.data, i)
            if total > 0xFFFFFFFF:
                total = (total & 0xFFFFFFFF) + (total >> 32)
            i += 2
        if i < length:
            total += self.data[i]
        total = (total & 0xFFFF) + (total >> 16)
        total += total >> 16
        checksum = (total & 0xFFFF) + length
        wr_u32(self.data, checksum_field, checksum)


class MetadataTables:
    def __init__(self, pe: PeImage) -> None:
        self.pe = pe
        self.data = pe.data
        meta = pe.metadata_root_offset()
        version_len = rd_u32(self.data, meta + 12)
        p = meta + 16 + version_len
        streams = rd_u16(self.data, p + 2)
        p += 4
        tilde = None
        strings = None
        for _ in range(streams):
            off = rd_u32(self.data, p)
            q = p + 8
            name_start = q
            while self.data[q] != 0:
                q += 1
            name = bytes(self.data[name_start:q])
            q = align_up(q + 1, 4)
            if name in (b"#~", b"#-"):
                tilde = meta + off
            elif name == b"#Strings":
                strings = meta + off
            p = q
        if tilde is None or strings is None:
            raise ValueError("metadata streams are missing")

        self.strings_off = strings
        heap_sizes = self.data[tilde + 6]
        valid = struct.unpack_from("<Q", self.data, tilde + 8)[0]
        rowp = tilde + 24
        self.rows = [0] * 64
        present = [i for i in range(64) if (valid >> i) & 1]
        for i in present:
            self.rows[i] = rd_u32(self.data, rowp)
            rowp += 4

        self.str_w = 4 if heap_sizes & 1 else 2
        self.guid_w = 4 if heap_sizes & 2 else 2
        self.blob_w = 4 if heap_sizes & 4 else 2
        self.table_offset: list[int | None] = [None] * 7
        cur = rowp
        for i in present:
            if i > 6:
                break
            self.table_offset[i] = cur
            if i < 6:
                cur += self.rows[i] * self.row_size(i)

    def simple_w(self, table: int) -> int:
        return 4 if self.rows[table] > 0xFFFF else 2

    def coded_w(self, tables: list[int], tag_bits: int) -> int:
        max_rows = max(self.rows[t] for t in tables)
        return 4 if max_rows > (1 << (16 - tag_bits)) else 2

    def row_size(self, table: int) -> int:
        s = self.str_w
        g = self.guid_w
        b = self.blob_w
        if table == 0:
            return 2 + s + 3 * g
        if table == 1:
            return self.coded_w([0, 26, 35, 1], 2) + 2 * s
        if table == 2:
            return 4 + 2 * s + self.coded_w([2, 1, 27], 2) + self.simple_w(4) + self.simple_w(6)
        if table == 3:
            return self.simple_w(4)
        if table == 4:
            return 2 + s + b
        if table == 5:
            return self.simple_w(6)
        if table == 6:
            return 4 + 2 + 2 + s + b + self.simple_w(8)
        raise ValueError(f"unsupported table {table}")

    def read_index(self, off: int, width: int) -> int:
        return rd_u16(self.data, off) if width == 2 else rd_u32(self.data, off)

    def get_string(self, index: int) -> str:
        start = self.strings_off + index
        end = start
        while self.data[end] != 0:
            end += 1
        return bytes(self.data[start:end]).decode("utf-8", errors="replace")

    def find_type(self, simple_name: str) -> int | None:
        off = self.table_offset[2]
        if off is None:
            return None
        size = self.row_size(2)
        for row in range(self.rows[2]):
            base = off + row * size + 4
            if self.get_string(self.read_index(base, self.str_w)) == simple_name:
                return row
        return None

    def type_method_list(self, row: int) -> int:
        off = self.table_offset[2]
        assert off is not None
        size = self.row_size(2)
        extends_w = self.coded_w([2, 1, 27], 2)
        field_w = self.simple_w(4)
        base = off + row * size + 4 + 2 * self.str_w + extends_w + field_w
        return self.read_index(base, self.simple_w(6))

    def method_rva_field_offset(self, row: int) -> int:
        off = self.table_offset[6]
        assert off is not None
        return off + row * self.row_size(6)

    def method_name(self, row: int) -> str:
        base = self.method_rva_field_offset(row)
        return self.get_string(self.read_index(base + 8, self.str_w))

    def find_method(self, type_simple_name: str, method_suffix: str) -> tuple[int, int]:
        type_row = self.find_type(type_simple_name)
        if type_row is None:
            raise ValueError(f"type {type_simple_name} was not found")
        start = self.type_method_list(type_row)
        end = self.type_method_list(type_row + 1) if type_row + 1 < self.rows[2] else self.rows[6] + 1
        for ridx in range(start, end):
            row = ridx - 1
            if self.method_name(row).endswith(method_suffix):
                rva_off = self.method_rva_field_offset(row)
                body_rva = rd_u32(self.data, rva_off)
                if body_rva == 0:
                    raise ValueError("method has no body")
                return body_rva, rva_off
        raise ValueError(f"method *{method_suffix} was not found in {type_simple_name}")


@dataclass
class EhClause:
    flags: int
    try_offset: int
    try_length: int
    handler_offset: int
    handler_length: int
    class_token_or_filter: int


class MethodBody:
    def __init__(self, max_stack: int, local_var_sig_tok: int, init_locals: bool, il: bytes, eh: list[EhClause]) -> None:
        self.max_stack = max_stack
        self.local_var_sig_tok = local_var_sig_tok
        self.init_locals = init_locals
        self.il = il
        self.eh = eh

    @staticmethod
    def parse(data: bytes | bytearray, off: int) -> "MethodBody":
        first = data[off]
        if first & 0x3 == 0x02:
            code_size = first >> 2
            return MethodBody(8, 0, False, bytes(data[off + 1 : off + 1 + code_size]), [])
        if first & 0x3 != 0x03:
            raise ValueError("unknown method body header")
        flags_size = rd_u16(data, off)
        header_words = flags_size >> 12
        header_len = header_words * 4
        max_stack = rd_u16(data, off + 2)
        code_size = rd_u32(data, off + 4)
        local_var_sig_tok = rd_u32(data, off + 8)
        init_locals = bool(flags_size & 0x10)
        il_off = off + header_len
        il = bytes(data[il_off : il_off + code_size])
        eh: list[EhClause] = []
        if flags_size & 0x08:
            sect = align_up(il_off + code_size, 4)
            while True:
                kind = data[sect]
                is_fat = bool(kind & 0x40)
                more = bool(kind & 0x80)
                if is_fat:
                    data_size = rd_u32(data, sect) >> 8
                    n = (data_size - 4) // 24
                    p = sect + 4
                    for _ in range(n):
                        eh.append(EhClause(rd_u32(data, p), rd_u32(data, p + 4), rd_u32(data, p + 8), rd_u32(data, p + 12), rd_u32(data, p + 16), rd_u32(data, p + 20)))
                        p += 24
                else:
                    data_size = data[sect + 1]
                    n = (data_size - 4) // 12
                    p = sect + 4
                    for _ in range(n):
                        eh.append(EhClause(rd_u16(data, p), rd_u16(data, p + 2), data[p + 4], rd_u16(data, p + 5), data[p + 7], rd_u32(data, p + 8)))
                        p += 12
                if not more:
                    break
                sect = align_up(sect + data_size, 4)
        return MethodBody(max_stack, local_var_sig_tok, init_locals, il, eh)

    def build_with_guard(self, arg_index: int, value: int) -> bytes:
        guard = build_guard(arg_index, value)
        new_il = guard + self.il
        flags = 0x03
        if self.init_locals:
            flags |= 0x10
        if self.eh:
            flags |= 0x08
        flags_size = (3 << 12) | flags
        out = bytearray()
        out += struct.pack("<HHII", flags_size, max(self.max_stack, 2), len(new_il), self.local_var_sig_tok)
        out += new_il
        if self.eh:
            out += b"\0" * ((4 - len(out) % 4) % 4)
            data_size = 4 + len(self.eh) * 24
            out += struct.pack("<I", 0x01 | 0x40 | (data_size << 8))
            glen = len(guard)
            for clause in self.eh:
                is_filter = bool(clause.flags & 0x1)
                last = clause.class_token_or_filter + glen if is_filter else clause.class_token_or_filter
                out += struct.pack(
                    "<IIIIII",
                    clause.flags,
                    clause.try_offset + glen,
                    clause.try_length,
                    clause.handler_offset + glen,
                    clause.handler_length,
                    last,
                )
        return bytes(out)


def build_guard(arg_index: int, value: int) -> bytes:
    out = bytearray()
    if 0 <= arg_index <= 3:
        out.append(0x02 + arg_index)
    else:
        out += bytes([0x0E, arg_index])
    if 0 <= value <= 8:
        out.append(0x16 + value)
    elif value == -1:
        out.append(0x15)
    elif -128 <= value <= 127:
        out += bytes([0x1F, value & 0xFF])
    else:
        out.append(0x20)
        out += struct.pack("<i", value)
    out += b"\x33\x01\x2A"
    return bytes(out)


def patch_camera_toast(source: Path, output: Path) -> str:
    pe = PeImage(source.read_bytes())
    tables = MetadataTables(pe)
    body_rva, rva_field_offset = tables.find_method("SynergyUIService", "ExceptionCallback")
    body_offset = pe.rva_to_offset(body_rva)
    if body_offset is None:
        raise ValueError("method body RVA cannot be mapped")
    body = MethodBody.parse(pe.data, body_offset)
    guard = build_guard(1, 3)
    if body.il.startswith(guard):
        output.write_bytes(bytes(pe.data))
        return "already-patched"
    new_body = body.build_with_guard(1, 3)
    new_rva = pe.append_section(".mipatch", new_body, IL_SECTION_CHARACTERISTICS)
    wr_u32(pe.data, rva_field_offset, new_rva)
    pe.update_checksum()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(bytes(pe.data))
    return "patched"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = patch_camera_toast(args.source, args.output)
    print(result)


if __name__ == "__main__":
    main()
