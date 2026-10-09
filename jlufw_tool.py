#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jlufw_tool.py - JieLi JLUFW firmware offline toolbox v2 (full decryption version)
=================================================================================
Reverse-engineered from: SincoOTA.apk (com.sinco.ota v1.0.10), libjl_ota_auth.so (arm64, not stripped)
  parse_fw_info @0x2384  main firmware parsing function
  decrypt       @0x2250  stream decryption
  func_296c     @0x296c  tail block: 32B key block -> 16bit decryption key
  CRC16 table   @0x0E18  16-entry nibble lookup table (poly 0x1021)

Recovered format (all verified via round-trip on synthetic firmware):
  Firmware header 64B:
    Stored form: byte0 = ~byte0; byte1..63 XORed byte-wise with the "key stream"
    Key stream:  16bit shift register, seed 0xFFFF, per byte: evolve first, then XOR (low 8 bits)
    Evolution:   new = rol16(old,1), then new.bit5 ^= old.bit15, new.bit12 ^= old.bit15
    Plaintext layout: [0:2]=CRC16(hdr[2:64])  [2:4]=CRC16(raw block-table bytes)
                      [4:8]=u32 declared total file length  [8:10]=u16 block count
  Block record 80B each (immediately after header):
    Stored form: byte0 as-is; byte1..79 XORed with key stream (seed 0xFFFF, reseeded per record)
    Plaintext layout: [0]=type  [8]=u32 data file offset  [16]=u32 data length
                      [20]=u32 encrypted-region start (within block)  [24]=u32 encrypted-region length (0=plaintext)
                      [64:74]=block name (ASCII, 10B)
    Note: block-table CRC is computed over the file's raw bytes (not de-obfuscated)
  tail.bin block data (raw bytes inside the file):
    [0x00:0x20] 32B key block
    [0x20:0x22] CRC16(key block)
    [0x22:0x26] magic 0x36659213 (LE)
    [0x26:0x28] magic 0x4273 (LE)
  Decryption key (func_296c, input: 32B key block K):
    s = sum(K[0..13]) + K[15] + (K[14]^K[16])        (32bit addition)
    base = s & 0xFF;  base<0x11 -> 0x55; base>0xDF -> 0xAA
    key.bit[i] = (base > (K[15-i] ^ K[16+i]) & 0xFF)   for i=0..15
    i.e. bit0=K[15]^K[16] ... bit15=K[0]^K[31]
  decrypt(buf, key, file_pos): process in <=32B chunks
    per chunk state = key ^ (file_pos>>2)
    within chunk byte0: XOR first, then evolve; byte1..n: evolve first, then XOR (low 8 bits)
    file_pos advances with the position inside the chunk (note: seed uses the chunk's start offset in the file)

CLI usage:
  python jlufw_tool.py info    <firmware>
  python jlufw_tool.py verify  <firmware>
  python jlufw_tool.py list    <firmware>
  python jlufw_tool.py extract <firmware> [-o output_dir]   # auto-decrypt
  python jlufw_tool.py dump    <firmware> [-n bytes]
  python jlufw_tool.py hexdump <firmware> <block_name> [--limit N]
"""

import argparse
import os
import struct
import sys

# ---------------------------------------------------------------- constants
HDR_SIZE = 0x40
REC_SIZE = 0x50
CHUNK = 0x20                      # decrypt reseeds the key stream every 32B chunk
TAIL_MAGIC_U32 = 0x36659213
TAIL_MAGIC_U16 = 0x4273

ERR_MEANING = {
    0:    "Success",
    -1:   "Firmware header CRC16 check failed",
    -2:   "File length declared at header[4:8] exceeds actual file size",
    -3:   "Block record table CRC16 check failed",
    -4:   "tail.bin magic number mismatch",
    -5:   "Embedded string in tail block does not match expected value",
    -6:   "tail block key-block CRC16 check failed",
    -100: "tail.bin / config.dat block not found",
}

# ---------------------------------------------------------------- primitives
def crc16_ccitt(data: bytes, init: int = 0x0000) -> int:
    """CRC16-CCITT (poly 0x1021, init 0, MSB-first) - equivalent to the .so's nibble lookup table"""
    crc = init & 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return crc


def ks_update(s: int) -> int:
    """16bit shift-register evolution (shared by decrypt@0x2298 / header and record de-obfuscation)"""
    s &= 0xFFFF
    n = ((s << 1) | (s >> 15)) & 0xFFFF          # rol16
    if s & 0x8000:                               # old.bit15 serves as the two tap bits
        n ^= (1 << 5) | (1 << 12)
    return n


def _ks_stream_xor(buf: bytearray, start: int, end: int, seed: int = 0xFFFF):
    """Apply or remove the key stream on buf[start:end] (XOR, symmetric)"""
    s = seed & 0xFFFF
    for i in range(start, end):
        s = ks_update(s)
        buf[i] ^= s & 0xFF


def deobf_header(raw64: bytes) -> bytearray:
    """Firmware header de-obfuscation: byte0 inverted, byte1..63 XORed with key stream"""
    b = bytearray(raw64[:HDR_SIZE])
    b[0] ^= 0xFF
    _ks_stream_xor(b, 1, HDR_SIZE)
    return b


def obf_header(plain64: bytes) -> bytes:
    """Firmware header obfuscation (symmetric to de-obfuscation; used to generate test firmware)"""
    return bytes(deobf_header(plain64))


def deobf_record(raw80: bytes) -> bytearray:
    """Block-record de-obfuscation: byte0 as-is, byte1..79 XORed with key stream (reseeded per record)"""
    b = bytearray(raw80[:REC_SIZE])
    _ks_stream_xor(b, 1, REC_SIZE)
    return b


def obf_record(plain80: bytes) -> bytes:
    return bytes(deobf_record(plain80))


def derive_key(kblk: bytes) -> int:
    """func_296c: 32B key block -> 16bit decryption key"""
    if len(kblk) < 32:
        raise ValueError("Key block must be 32 bytes")
    K = kblk
    s = sum(K[0:14]) & 0xFFFFFFFF
    s = (s + K[15] + (K[14] ^ K[16])) & 0xFFFFFFFF
    base = s & 0xFF
    if base < 0x11:
        base = 0x55
    elif base > 0xDF:
        base = 0xAA
    key = 0
    for i in range(16):
        pair = K[15 - i] ^ K[16 + i]
        if base > (pair & 0xFF):
            key |= (1 << i)
    return key


def jl_decrypt(buf: bytearray, key: int, file_pos: int, start: int = 0, length: int = 0):
    """decrypt@0x2250: decrypt buf[start:start+length] in place
    file_pos = start offset of the data block within the firmware file (used as seed; note: not the absolute offset of the encrypted region)"""
    n = length if length else (len(buf) - start)
    pos = file_pos & 0xFFFFFFFF
    i = start
    remaining = n
    while remaining > 0:
        chunk = min(remaining, CHUNK)
        state = (key ^ (pos >> 2)) & 0xFFFF
        buf[i] ^= state & 0xFF                    # byte0: XOR first
        for j in range(1, chunk):                 # rest: evolve first, then XOR
            state = ks_update(state)
            buf[i + j] ^= state & 0xFF
        i += chunk
        pos = (pos + chunk) & 0xFFFFFFFF
        remaining -= chunk


# ---------------------------------------------------------------- parser
class Firmware:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.raw = f.read()
        self.size = len(self.raw)
        self.errors = []
        self.warnings = []
        self.blocks = []
        self.tail = None          # tail.bin block dict, or None
        self.key = None           # derived 16bit decryption key
        self._parse()

    def _parse(self):
        if self.size < HDR_SIZE:
            self.errors.append("File smaller than 64 bytes, not a JLUFW firmware")
            return
        hdr = deobf_header(self.raw[:HDR_SIZE])
        self.hdr = hdr

        self.hdr_crc_stored = struct.unpack_from("<H", hdr, 0)[0]
        self.hdr_crc_calc = crc16_ccitt(bytes(hdr[2:HDR_SIZE]))
        self.hdr_crc_ok = (self.hdr_crc_stored == self.hdr_crc_calc)

        self.decl_file_size = struct.unpack_from("<I", hdr, 4)[0]
        self.size_ok = self.decl_file_size <= self.size

        self.block_count = struct.unpack_from("<H", hdr, 8)[0]
        self.tbl_crc_stored = struct.unpack_from("<H", hdr, 2)[0]

        tbl_len = self.block_count * REC_SIZE
        tbl_end = HDR_SIZE + tbl_len
        if self.block_count == 0 or tbl_end > self.size:
            self.errors.append(
                f"Block table out of bounds / abnormal count: count={self.block_count}, need {tbl_len}B, file {self.size}B")
            self.tbl_crc_ok = False
        else:
            self.tbl_crc_calc = crc16_ccitt(self.raw[HDR_SIZE:tbl_end])   # raw bytes!
            self.tbl_crc_ok = (self.tbl_crc_stored == self.tbl_crc_calc)
            for i in range(self.block_count):
                r = deobf_record(self.raw[HDR_SIZE + i * REC_SIZE:
                                          HDR_SIZE + (i + 1) * REC_SIZE])
                b = {
                    "index": i,
                    "type": r[0],
                    "offset": struct.unpack_from("<I", r, 8)[0],
                    "length": struct.unpack_from("<I", r, 16)[0],
                    "enc_start": struct.unpack_from("<I", r, 20)[0],
                    "enc_len": struct.unpack_from("<I", r, 24)[0],
                    "name": r[64:74].split(b"\x00")[0].decode("ascii", "replace"),
                }
                if b["offset"] + b["length"] > self.size:
                    self.warnings.append(
                        f"Block[{i}] {b['name']} out of bounds: off={b['offset']:#x} len={b['length']:#x}")
                self.blocks.append(b)

        self._parse_tail()

    def _parse_tail(self):
        self.tail_crc_ok = None
        self.tail_magic_ok = None
        t = self.find_block("tail.bin")
        if not t:
            return
        self.tail = t
        d = self.raw[t["offset"]:t["offset"] + t["length"]]
        if len(d) < 0x28:
            self.warnings.append(f"tail.bin data shorter than 0x28 bytes (actual {len(d)})")
            return
        self.tail_data = d
        m32 = struct.unpack_from("<I", d, 0x22)[0]
        m16 = struct.unpack_from("<H", d, 0x26)[0]
        self.tail_magic_ok = (m32 == TAIL_MAGIC_U32 and m16 == TAIL_MAGIC_U16)
        kblk = d[0:0x20]
        crc_stored = struct.unpack_from("<H", d, 0x20)[0]
        self.tail_crc_ok = (crc16_ccitt(kblk) == crc_stored)
        if self.tail_crc_ok:
            self.key = derive_key(kblk)

    # -------------------------------------------------- helpers
    def find_block(self, name: str):
        for b in self.blocks:
            if b["name"] == name:
                return b
        return None

    def block_data(self, blk: dict, decrypt: bool = True) -> bytes:
        """Get block data; auto-decrypt if the block has an encrypted region and the key is available"""
        data = bytearray(self.raw[blk["offset"]:blk["offset"] + blk["length"]])
        if (decrypt and blk["enc_len"] and self.key is not None
                and blk["enc_start"] + blk["enc_len"] <= len(data)):
            jl_decrypt(data, self.key, blk["offset"],
                       blk["enc_start"], blk["enc_len"])
            blk = dict(blk)
            blk["_decrypted"] = True
        return bytes(data)

    def all_checks(self):
        """Return [(name, passed, detail), ...]"""
        checks = [
            ("Firmware header CRC16", self.hdr_crc_ok,
             f"stored {self.hdr_crc_stored:#06x} / computed {self.hdr_crc_calc:#06x}"),
            ("Block table CRC16", self.tbl_crc_ok,
             f"stored {self.tbl_crc_stored:#06x} / computed {getattr(self,'tbl_crc_calc',0):#06x}"),
            ("Declared length <= actual length", self.size_ok,
             f"declared {self.decl_file_size} / actual {self.size}"),
        ]
        if self.tail_magic_ok is not None:
            checks.append(("tail.bin magic", self.tail_magic_ok, "0x36659213 + 0x4273"))
        if self.tail_crc_ok is not None:
            checks.append(("tail key block CRC16", self.tail_crc_ok, ""))
        if self.key is not None:
            checks.append(("Decryption key derived", True, f"key={self.key:#06x}"))
        return checks

    def overall_ok(self) -> bool:
        return (not self.errors and not self.warnings
                and all(v for _, v, _ in self.all_checks()))

    # -------------------------------------------------- CLI
    def cmd_info(self):
        print(f"File          : {self.path}")
        print(f"Actual size    : {self.size} bytes (0x{self.size:X})")
        print()
        print("--- Firmware header (64B, de-obfuscated with real key stream) ---")
        for name, ok, detail in self.all_checks():
            print(f"  [{'✓' if ok else '✗'}] {name:14s} {detail}")
        print(f"  Block count: {self.block_count}")
        print()
        self.cmd_list()
        if self.errors:
            print("\n!! Errors:")
            for e in self.errors:
                print("   ", e)
        if self.warnings:
            print("\n!! Warnings:")
            for w in self.warnings:
                print("   ", w)

    def cmd_verify(self):
        ok = True
        for name, v, detail in self.all_checks():
            print(f"  [{'PASS' if v else 'FAIL'}] {name}  {detail}")
            ok = ok and v
        if self.errors or self.warnings:
            ok = False
            for e in self.errors + self.warnings:
                print("  [WARN]", e)
        print("\nOverall verdict:", "✓ verification passed" if ok else "✗ anomalies found")
        return 0 if ok else 1

    def cmd_list(self):
        print(f"{'idx':>3}  {'type':>4}  {'offset':>10}  {'length':>10}  "
              f"{'enc@':>8}  {'enc_len':>8}  name")
        print("-" * 72)
        for b in self.blocks:
            enc = f"{b['enc_start']:#x}" if b["enc_len"] else "-"
            encl = f"{b['enc_len']:#x}" if b["enc_len"] else "-"
            print(f"{b['index']:>3}  {b['type']:#04x}  {b['offset']:#010x}  "
                  f"{b['length']:#010x}  {enc:>8}  {encl:>8}  {b['name']}")

    def cmd_extract(self, outdir: str):
        os.makedirs(outdir, exist_ok=True)
        for b in self.blocks:
            data = self.block_data(b)
            tag = " [decrypted]" if b["enc_len"] and self.key is not None else \
                  (" [encrypted region, no key]" if b["enc_len"] else "")
            safe = (b["name"].replace("/", "_").replace("\\", "_")
                    or f"block_{b['index']}")
            if not safe.lower().endswith((".bin", ".dat", ".ufw", ".bfu")):
                safe += ".bin"
            p = os.path.join(outdir, f"{b['index']:02d}_{safe}")
            with open(p, "wb") as f:
                f.write(data)
            print(f"  -> {p}  ({len(data)} bytes){tag}")
        print(f"\nExported {len(self.blocks)} blocks to {outdir}")

    def cmd_dump(self, n: int):
        print("--- Firmware header (after de-obfuscation) ---")
        _hexprint(self.hdr[:min(n, HDR_SIZE)])
        print("\n--- Firmware header (raw bytes) ---")
        _hexprint(self.raw[:min(n, HDR_SIZE)])

    def cmd_hexdump(self, name: str, limit: int):
        b = self.find_block(name)
        if not b:
            print(f"Block not found: {name}", file=sys.stderr)
            return 1
        data = self.block_data(b)
        if limit:
            data = data[:limit]
        print(f"--- {b['name']}  off={b['offset']:#x} len={len(data):#x} ---")
        _hexprint(data)
        return 0


def _hexprint(data: bytes, base: int = 0):
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{c:02x}" for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print(f"  {base + i:08x}: {hexs:<48}  {asc}")


def main():
    ap = argparse.ArgumentParser(
        prog="jlufw_tool.py",
        description="JieLi JLUFW firmware offline toolbox v2 (full decryption, reverse-engineered from SincoOTA.apk)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, help_ in [("info", "Parse firmware header and block table"),
                        ("verify", "Verify integrity"),
                        ("list", "List all blocks")]:
        p = sub.add_parser(name, help=help_)
        p.add_argument("file")

    p = sub.add_parser("extract", help="Export all blocks (auto-decrypt)")
    p.add_argument("file")
    p.add_argument("-o", "--out", default="./jlufw_out")

    p = sub.add_parser("dump", help="Hex dump firmware header")
    p.add_argument("file")
    p.add_argument("-n", "--bytes", type=lambda x: int(x, 0), default=64)

    p = sub.add_parser("hexdump", help="Hex view a block (auto-decrypt)")
    p.add_argument("file")
    p.add_argument("block")
    p.add_argument("--limit", type=lambda x: int(x, 0), default=0)

    args = ap.parse_args()
    if not os.path.isfile(args.file):
        print(f"File does not exist: {args.file}", file=sys.stderr)
        return 2

    fw = Firmware(args.file)
    if args.cmd == "info":
        fw.cmd_info()
    elif args.cmd == "verify":
        return fw.cmd_verify()
    elif args.cmd == "list":
        fw.cmd_list()
    elif args.cmd == "extract":
        fw.cmd_extract(args.out)
    elif args.cmd == "dump":
        fw.cmd_dump(args.bytes)
    elif args.cmd == "hexdump":
        return fw.cmd_hexdump(args.block, args.limit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
