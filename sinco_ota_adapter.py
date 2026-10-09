#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sinco_ota_adapter.py - SincoOTA firmware upgrade flow - PC adaptation script (v2, protocol calibrated)
======================================================================================================

Reenacts SincoOTA.apk (com.sinco.ota)'s "firmware upgrade runtime trajectory" on a Windows PC.
The protocol layer is calibrated against the JieLi official RCSP SDK (com.jieli.jl_bt_ota, v1.9.2) disassembled inside the APK.

[SincoOTA actual runtime trajectory] (reverse-engineered from APK + JieLi official SDK smali, verified)
  1. Select a .fwsc firmware file
  2. Parse firmware: header (16-bit LFSR de-obfuscation) -> split partitions via plaintext inner manifest (see Firmware)
  3. Device model match check
  4. Android BLE connect (GATT, service 0000AE00...) -> RCSP channel established
  5. (optional) RCSP auth RcspAuth
  6. Query device info getDeviceInfo (0x03) / getMD5 (0xd4)
  7. readUpgradeFileFlag (0xe1) -> take the offset/length of the "upgrade flag" region in the firmware
  8. inquiryDeviceCanOTA (0xe2, send that flag region back to the device to authenticate firmware compatibility)
  9. notifyUpdateContentSize (0xe8, total firmware size)
 10. enterUpdateMode (0xe3) enter OTA mode
 11. ★ Data stage (device-pull model): device repeatedly sends CMD_OTA_SEND_FIRMWARE_UPDATE_BLOCK (0xe5)
         = [offset(4, big-endian)][len(2, big-endian)] requesting one block; this side reads that position in the firmware
         and returns it with the 0xe5 "response frame" [status=0][sn][raw firmware bytes]. Loop until the firmware is fully sent.
 12. queryUpdateResult (0xe6) query result / exitUpdateMode (0xe4)
 13. rebootDevice (0xe7, param 0=reboot) -> device reboots into the new firmware

[RCSP frame wire format] (from RcspParser / BasePacket smali disassembly, authoritative)
  FE DC BA | HDR(1) | OP(1) | LEN(2, big-endian, = byte count of the PARAM that follows) | PARAM(LEN) | EF(1)
    HDR = (type<<7) | (hasResponse<<6)   // type: 1=command 0=response
    PARAM(command) = [sn(1)] [if OP==0x01 then xmOp(1)] [paramData...]
    PARAM(response) = [status(1)] [sn(1)] [paramData...]
    Note: this SDK frame has NO CRC, ends with EF; reliability is guaranteed by the BLE layer.

[What this script does]
  * File side (verified): use the plaintext inner manifest at 0x26acc inside the firmware to reliably split each partition.
  * Transport side (reenacted per the above trajectory, needs real-device testing):
      - ble  : bleak runs RCSP-over-BLE on PC (default JL standard UUID, can be changed)
      - uart : pyserial runs RCSP-over-UART (truly Bluetooth-free; same frame format as BLE, no extra encapsulation)

[Usage]
  python sinco_ota_adapter.py list-blocks <firmware>        # list partitions inside firmware (verify parsing)
  python sinco_ota_adapter.py info <firmware>               # header info + verification
  python sinco_ota_adapter.py upgrade <firmware> --transport ble --target "JL_XXXX"
  python sinco_ota_adapter.py upgrade <firmware> --transport uart --port COM3 --baud 115200

Dependencies (only imported when the corresponding transport is used):
  pip install bleak        # ble backend
  pip install pyserial     # uart backend
"""

import argparse
import os
import struct
import sys
import time

# Reuse the verified low-level algorithms (header de-obfuscation / CRC16); do not touch the broken record-table parsing in jlufw_tool
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jlufw_tool import crc16_ccitt, deobf_header  # noqa: E402

APP_TITLE = "SincoOTA-PC Adapter Script"

# Import name kept compatible with the old GUI (old version SOF was a single byte; the prefix is now 3 bytes FE DC BA)
RCSP_SOF = 0xFE
RCSP_PREFIX = b"\xFE\xDC\xBA"
RCSP_END = 0xEF

# JieLi RCSP BLE standard UUID (default; if your device differs, override with --write-uuid/--notify-uuid)
DEFAULT_SERVICE_UUID = "0000AE00-0000-1000-8000-00805F9B34FB"
DEFAULT_WRITE_UUID = "0000AE01-0000-1000-8000-00805F9B34FB"
DEFAULT_NOTIFY_UUID = "0000AE02-0000-1000-8000-00805F9B34FB"


# ----------------------------------------------------------------------------
# 1) Firmware parsing (file side, verified)
# ----------------------------------------------------------------------------
HDR_SIZE = 0x40
KNOWN_BLOCK_NAMES = (
    b"edr_ota2.bin", b"uart_update.bin", b"ble_ota.bin", b"sd_update2.bin",
    b"usb_update2.bin", b"ble_app_ota.bin", b"uart_user.bin", b"AC636N_TRANS",
    b"app_dir_head", b"uboot", b"isd_config.ini", b"config", b"exflash",
    b"norflash", b"vm", b"bt_ota.bin", b"logo.bin",
)


class Firmware:
    """Parse .fwsc: header de-obfuscation + split partitions via the plaintext inner manifest (does not depend on the 32-bit TOC key)."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.raw = f.read()
        self.size = len(self.raw)
        self.blocks = []
        self._parse_header()
        self._parse_manifest()

    def _parse_header(self):
        self.hdr = deobf_header(self.raw[:HDR_SIZE])
        self.hdr_crc_stored = struct.unpack_from("<H", self.hdr, 0)[0]
        self.hdr_crc_calc = crc16_ccitt(bytes(self.hdr[2:HDR_SIZE]))
        self.hdr_crc_ok = (self.hdr_crc_stored == self.hdr_crc_calc)
        self.decl_size = struct.unpack_from("<I", self.hdr, 4)[0]
        self.block_count = struct.unpack_from("<H", self.hdr, 8)[0]
        tail = self.hdr[0x10:0x40]
        self.chip = tail.split(b"\x00")[0].decode("ascii", "replace")

    def _parse_manifest(self):
        """Locate the plaintext inner manifest. Manifest entry format (verified):
            [16-byte header][16-byte name field (zero-padded)]  —— fixed 32B per entry, laid out contiguously in the file
            header = [hash:4][offset:4][length:4][flags:4]
        """
        data = self.raw
        cands = []
        for name in KNOWN_BLOCK_NAMES:
            start = 0
            while True:
                i = data.find(name, start)
                if i < 0:
                    break
                if i >= 16:
                    hsh, off, length, flags = struct.unpack_from("<IIII", data, i - 16)
                    if 0x310 <= off < self.size and 0 < length <= self.size - off:
                        cands.append((off, length, name.decode("ascii", "replace"),
                                      flags, hsh, i))
                start = i + 1
        if not cands:
            return
        by_pos = {c[5]: c for c in cands}
        STRIDE = 32  # fixed 32B per entry: 16B header + 16B name field (zero-padded)

        def run_from(p):
            run = []
            while p in by_pos:
                e = by_pos[p]
                run.append(e)
                p = p + STRIDE
            return run

        best = []
        for c in cands:
            fwd = run_from(c[5])
            head = fwd[0]
            p = head[5]
            back = []
            while (p - STRIDE) in by_pos:
                prev = by_pos[p - STRIDE]
                back.insert(0, prev)
                p = prev[5]
            run = back + fwd
            if len(run) > len(best):
                best = run
        self.blocks = [{"name": c[2], "offset": c[0], "length": c[1],
                        "flags": c[3], "hash": c[4]} for c in best]

    def block_data(self, blk):
        return self.raw[blk["offset"]:blk["offset"] + blk["length"]]


# ----------------------------------------------------------------------------
# 2) RCSP protocol frame (calibrated against the SDK, see module docstring)
# ----------------------------------------------------------------------------
# Real RCSP command opcodes (disassembled from Command.smali)
CMD_DATA = 0x01
CMD_GET_TARGET_FEATURE_MAP = 0x02
CMD_GET_TARGET_INFO = 0x03
CMD_GET_DEV_MD5 = 0xD4
CMD_SETTINGS_COMMUNICATION_MTU = 0xD1
CMD_OTA_GET_DEVICE_UPDATE_FILE_INFO_OFFSET = 0xE1
CMD_OTA_INQUIRE_DEVICE_IF_CAN_UPDATE = 0xE2
CMD_OTA_ENTER_UPDATE_MODE = 0xE3
CMD_OTA_EXIT_UPDATE_MODE = 0xE4
CMD_OTA_SEND_FIRMWARE_UPDATE_BLOCK = 0xE5
CMD_OTA_GET_DEVICE_REFRESH_FIRMWARE_STATUS = 0xE6
CMD_REBOOT_DEVICE = 0xE7
CMD_OTA_NOTIFY_UPDATE_CONTENT_SIZE = 0xE8

# Device-pull model: the device requests a block with the 0xE5 command; this side returns the data with the 0xE5 response
OP_BLOCK = CMD_OTA_SEND_FIRMWARE_UPDATE_BLOCK


def rcsp_frame(op, param=b"", *, is_response=False, has_response=False,
               sn=0, xm_op=0):
    """Build an RCSP frame.

    HDR = (1<<7 if not is_response else 0) | (1<<6 if has_response else 0)
    PARAM(command) = [sn] [xmOp if op==0x01] [param]
    PARAM(response) = [status=0] [sn] [param]
    """
    hdr = ((0 if is_response else 1) << 7) | ((1 if has_response else 0) << 6)
    body = bytearray()
    if is_response:
        body.append(0x00)               # status: 0=success
        body.append(sn & 0xFF)
        body += param
    else:
        body.append(sn & 0xFF)
        if op == CMD_DATA:
            body.append(xm_op & 0xFF)
        body += param
    frame = bytearray(RCSP_PREFIX)
    frame.append(hdr & 0xFF)
    frame.append(op & 0xFF)
    frame += struct.pack(">H", len(body))   # LEN = byte count of PARAM
    frame += body
    frame.append(RCSP_END)
    return bytes(frame)


def rcsp_extract(buf, start=0):
    """Extract one complete RCSP frame from a byte stream.

    Returns (frame_dict, keep_from).
    frame_dict contains: op, type (1=command/0=response), has_response, status, sn, xm_op, param, raw
    If no complete frame is available, returns (None, keep_from) -- the caller keeps the unconsumed tail based on this.
    """
    i = buf.find(RCSP_PREFIX, start)
    if i < 0:
        # No prefix: keep the tail (a prefix may straddle the boundary) to avoid missing a frame
        return None, max(0, len(buf) - len(RCSP_PREFIX) + 1)
    if len(buf) - i < 7:                     # need at least prefix3 + HDR1 + OP1 + LEN2
        return None, i
    hdr = buf[i + 3]
    op = buf[i + 4]
    length = struct.unpack(">H", buf[i + 5:i + 7])[0]
    frame_end = i + 8 + length                # prefix3 + (HDR+OP+LEN total 4) + body + EF1
    if len(buf) < frame_end:
        return None, i                         # frame incomplete, wait for more data
    if buf[frame_end - 1] != RCSP_END:
        return None, i + 1                     # tail is not EF -> false prefix, skip this byte
    body = buf[i + 7:i + 7 + length]
    type_bit = (hdr >> 7) & 1
    has_resp = (hdr >> 6) & 1
    p = 0
    status = None
    sn = None
    xm_op = None
    if type_bit == 0:                          # response
        status = body[p]; p += 1
        sn = body[p]; p += 1
    else:                                      # command
        sn = body[p]; p += 1
        if op == CMD_DATA:
            xm_op = body[p]; p += 1
    param = bytes(body[p:])
    return {"op": op, "type": type_bit, "has_response": has_resp,
            "status": status, "sn": sn, "xm_op": xm_op, "param": param,
            "raw": bytes(buf[i:frame_end])}, frame_end


# ---- param construction for each command (calibrated against *Param.smali) ----
def pdu_target_info(mask=0xFFFFFFFF, platform=0x00):
    # GetTargetInfoParam: [mask(4, big-endian)][platform(1)]
    return struct.pack(">I", mask & 0xFFFFFFFF) + bytes([platform & 0xFF])


def pdu_mtu(mtu):
    # SettingsMtuParam: [mtu(2, big-endian)]
    return struct.pack(">H", mtu & 0xFFFF)


def pdu_notify_size(content_size, progress=0):
    # NotifyUpdateContentSizeParam: progress<=0 -> [size(4)]; otherwise [size(4)][progress(4)]
    if progress <= 0:
        return struct.pack(">I", content_size & 0xFFFFFFFF)
    return struct.pack(">II", content_size & 0xFFFFFFFF, progress & 0xFFFFFFFF)


def pdu_inquire(flag_data):
    # InquireUpdateParam: directly the upgrade-flag region bytes
    return flag_data


def pdu_reboot(param=0x00):
    # RebootDeviceParam: [param(1)]  0=reboot
    return bytes([param & 0xFF])


def parse_file_offset(resp_param):
    # UpdateFileOffsetResponse: [offset(4, big-endian)][len(2, big-endian)]
    if len(resp_param) >= 6:
        off = struct.unpack(">I", resp_param[0:4])[0]
        ln = struct.unpack(">H", resp_param[4:6])[0]
        return off, ln
    return None, None


def parse_block_request(param):
    # Device 0xE5 command: [offset(4, big-endian)][len(2, big-endian)]
    if len(param) >= 6:
        off = struct.unpack(">I", param[0:4])[0]
        ln = struct.unpack(">H", param[4:6])[0]
        return off, ln
    return None, None


# ----------------------------------------------------------------------------
# 3) Transport backend - replace Android BLE with a PC-runnable channel
# ----------------------------------------------------------------------------
class Transport:
    def connect(self):
        raise NotImplementedError

    def send(self, data: bytes):
        raise NotImplementedError

    def recv_raw(self, timeout=1.0) -> bytes:
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class BleTransport(Transport):
    """RCSP-over-BLE: reenact SincoOTA's original path on PC using bleak.
    Uses the JieLi standard OTA UUID by default; if your device differs, override with write_uuid/notify_uuid.
    """

    def __init__(self, target, write_uuid=None, notify_uuid=None, service_uuid=None,
                 mtu=None):
        self.target = target
        self.write_uuid = write_uuid or DEFAULT_WRITE_UUID
        self.notify_uuid = notify_uuid or DEFAULT_NOTIFY_UUID
        self.service_uuid = service_uuid
        self.req_mtu = mtu
        self._client = None
        self._loop = None
        self._thread = None
        self._buf = bytearray()

    def _bg(self):
        import asyncio
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run(self, coro):
        import asyncio
        if self._loop is None:
            raise RuntimeError("BLE not initialized")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=15)

    def _on_notify(self, _sender, data):
        self._buf.extend(data)

    def connect(self):
        try:
            import asyncio  # noqa: F401
            from bleak import BleakClient
        except ImportError:
            raise RuntimeError("Please install bleak first: pip install bleak")
        import threading
        self._thread = threading.Thread(target=self._bg, daemon=True)
        self._thread.start()
        for _ in range(60):
            if self._loop is not None:
                break
            time.sleep(0.05)
        self._client = BleakClient(self.target)

        async def _do():
            await self._client.connect()
            if self.req_mtu:
                try:
                    await self._client.exchange_mtu(self.req_mtu)
                except Exception:
                    pass
            await self._client.start_notify(self.notify_uuid, self._on_notify)

        self._run(_do())

    def send(self, data: bytes):
        async def _w():
            # Write without response for throughput; RCSP ACK is handled at the protocol layer (notify)
            await self._client.write_gatt_char(
                self.write_uuid, bytes(data), response=False)
        self._run(_w())

    def recv_raw(self, timeout=1.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._buf:
                out = bytes(self._buf)
                self._buf.clear()
                return out
            time.sleep(0.02)
        return b""

    def close(self):
        async def _c():
            try:
                await self._client.stop_notify(self.notify_uuid)
            except Exception:
                pass
            await self._client.disconnect()
        try:
            self._run(_c())
        except Exception:
            pass
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)


class UartTransport(Transport):
    """RCSP-over-UART: truly Bluetooth-free. Once the device exposes a serial port, RCSP frames are sent directly (same frame format as BLE)."""

    def __init__(self, port, baud=115200):
        self.port = port
        self.baud = baud
        self._ser = None

    def connect(self):
        try:
            import serial
        except ImportError:
            raise RuntimeError("Please install pyserial first: pip install pyserial")
        try:
            self._ser = serial.Serial(self.port, self.baud, timeout=0.05)
        except serial.SerialException as e:
            avail = []
            try:
                avail = [p.device for p in serial.tools.list_ports.comports()]
            except Exception:
                pass
            msg = "Cannot open serial port %s: %s" % (self.port, e)
            msg += ("\nAvailable ports: " + ", ".join(avail)) if avail else \
                   "\nNo available serial port found (is the device connected? driver needed?)"
            raise RuntimeError(msg)

    def send(self, data: bytes):
        self._ser.write(bytes(data))

    def recv_raw(self, timeout=1.0):
        self._ser.timeout = timeout
        buf = bytearray()
        # Read until at least one complete frame boundary (EF) appears, or timeout
        while True:
            b = self._ser.read(1)
            if not b:
                break
            buf += b
            # Roughly: once an FE DC BA prefix appears, stop a moment after reading EF, to avoid packet sticking;
            # here we simply read until timeout, and rcsp_extract will reassemble frames on its own
            if len(buf) > 64 and buf.rfind(RCSP_PREFIX) >= 0:
                # Already contains a prefix; read a little more then return, leaving reassembly to rcsp_extract
                break
        return bytes(buf)

    def close(self):
        if self._ser:
            self._ser.close()


# ----------------------------------------------------------------------------
# 4) OTA session (reenacts SincoOTA runtime trajectory, device-pull model)
# ----------------------------------------------------------------------------
class OtaSession:
    def __init__(self, fw: Firmware, transport: Transport, mtu=244, log_fn=None):
        self.fw = fw
        self.tp = transport
        self.mtu = mtu
        self._log = log_fn or (lambda *a: print("[OTA]", *a))
        self._sn = 0
        self._rbuf = bytearray()
        self._served = 0

    def log(self, *a):
        self._log(" ".join(str(x) for x in a))

    # ---- Frame send/receive ----
    def _next_sn(self):
        self._sn = (self._sn + 1) & 0xFF
        if self._sn == 0:
            self._sn = 1
        return self._sn

    def _send_cmd(self, op, param=b"", has_response=True, timeout=3.0):
        sn = self._next_sn()
        self.tp.send(rcsp_frame(op, param, is_response=False,
                                has_response=has_response, sn=sn))
        if not has_response:
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            f = self._read_frame(timeout=min(0.3, deadline - time.time()))
            if f is None:
                continue
            # During the data stage a block request from the device may arrive early; handle it on the fly
            if f["type"] == 1 and f["op"] == OP_BLOCK:
                self._respond_block(f)
                continue
            if f["type"] == 0 and f["op"] == op:
                return f
        return None

    def _read_frame(self, timeout=1.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            f, keep = rcsp_extract(self._rbuf, 0)
            if f is not None:
                self._rbuf = self._rbuf[keep:]
                return f
            raw = self.tp.recv_raw(timeout=min(0.2, deadline - time.time()))
            if raw:
                self._rbuf += raw
        return None

    def _respond_block(self, req):
        """Device sends a 0xE5 command [offset][len] -> reply with a 0xE5 response [status][sn][data]."""
        off, ln = parse_block_request(req["param"])
        if off is None:
            self.log("  [block request] invalid param:", req["param"].hex())
            return
        ln = min(ln, self.mtu - 8) if self.mtu else ln
        if off + ln > self.fw.size:
            ln = max(0, self.fw.size - off)
        data = self.fw.raw[off:off + ln]
        self.tp.send(rcsp_frame(OP_BLOCK, data, is_response=True,
                                has_response=False, sn=req["sn"]))
        self._served += ln
        self.log("  block request off=0x%08X len=%d  sent %d/%d" %
                 (off, ln, self._served, self.fw.size))

    # ---- Trajectory ----
    def run(self):
        self.log("① Connect transport layer ...")
        self.tp.connect()

        self.log("② Device info getDeviceInfo(0x03) ...")
        r = self._send_cmd(CMD_GET_TARGET_INFO, pdu_target_info())
        self.log("   resp:", (r["raw"].hex() if r else "(none/timeout)"))

        self.log("③ Device MD5 getMD5(0xD4) ...")
        r = self._send_cmd(CMD_GET_DEV_MD5)
        self.log("   resp:", (r["raw"].hex() if r else "(none/timeout)"))

        self.log("④ Read upgrade flag readUpgradeFileFlag(0xE1) ...")
        r = self._send_cmd(CMD_OTA_GET_DEVICE_UPDATE_FILE_INFO_OFFSET)
        flag_off, flag_len = parse_file_offset(r["param"]) if r else (None, None)
        self.log("   flag_off=0x%X flag_len=%d" %
                 (flag_off if flag_off is not None else -1,
                  flag_len if flag_len is not None else -1))

        flag_data = b""
        if flag_off is not None and flag_len:
            flag_data = self.fw.raw[flag_off:flag_off + flag_len]

        self.log("⑤ Firmware compatibility inquiry inquiryDeviceCanOTA(0xE2) ...")
        r = self._send_cmd(CMD_OTA_INQUIRE_DEVICE_IF_CAN_UPDATE,
                           pdu_inquire(flag_data))
        self.log("   resp:", (r["raw"].hex() if r else "(none/timeout)"))

        self.log("⑥ Notify total size notifyUpdateContentSize(0xE8) size=%d ..." % self.fw.size)
        r = self._send_cmd(CMD_OTA_NOTIFY_UPDATE_CONTENT_SIZE,
                           pdu_notify_size(self.fw.size))
        self.log("   resp:", (r["raw"].hex() if r else "(none/timeout)"))

        self.log("⑦ Enter OTA mode enterUpdateMode(0xE3) ...")
        r = self._send_cmd(CMD_OTA_ENTER_UPDATE_MODE)
        self.log("   resp:", (r["raw"].hex() if r else "(none/timeout)"))

        self.log("⑧ Negotiate MTU settingsMtu(0xD1) mtu=%d ..." % self.mtu)
        r = self._send_cmd(CMD_SETTINGS_COMMUNICATION_MTU, pdu_mtu(self.mtu))
        self.log("   resp:", (r["raw"].hex() if r else "(none/timeout)"))

        self.log("⑨ Data stage: waiting for device 0xE5 block request and returning firmware (device-pull model) ...")
        self._data_phase()

        self.log("⑩ Query result queryUpdateResult(0xE6) ...")
        r = self._send_cmd(CMD_OTA_GET_DEVICE_REFRESH_FIRMWARE_STATUS)
        self.log("   resp:", (r["raw"].hex() if r else "(none/timeout)"))

        self.log("⑪ Exit OTA exitUpdateMode(0xE4) ...")
        r = self._send_cmd(CMD_OTA_EXIT_UPDATE_MODE)
        self.log("   resp:", (r["raw"].hex() if r else "(none/timeout)"))

        self.log("⑫ Reboot device rebootDevice(0xE7,0) ...")
        r = self._send_cmd(CMD_REBOOT_DEVICE, pdu_reboot(0))
        self.log("   resp:", (r["raw"].hex() if r else "(none/timeout)"))

        self.tp.close()
        self.log("Done. Device should reboot into the new firmware (returned %d bytes total)" % self._served)

    def _data_phase(self):
        served_target = self.fw.size
        last_req = time.time()
        idle_timeout = 4.0
        while True:
            f = self._read_frame(timeout=1.0)
            if f is None:
                if time.time() - last_req > idle_timeout:
                    self.log("   Device stopped requesting (idle timeout), data stage ended")
                    break
                continue
            if f["type"] == 1 and f["op"] == OP_BLOCK:
                self._respond_block(f)
                last_req = time.time()
                if self._served >= served_target:
                    self.log("   All firmware bytes returned, data stage ended")
                    break
            else:
                self.log("   [Data stage] ignoring frame op=0x%X type=%d" %
                         (f["op"], f["type"]))
        self.log("   Data stage ended, responded %d bytes total" % self._served)


# ----------------------------------------------------------------------------
# 5) CLI
# ----------------------------------------------------------------------------
def cmd_list_blocks(fw):
    print("Firmware: %s  (%d bytes, chip %s)" % (fw.path, fw.size, fw.chip))
    print("Inner manifest parsed into %d partitions:" % len(fw.blocks))
    print("%-4s %-18s %10s %10s %10s" % ("#", "name", "offset", "length", "flags"))
    print("-" * 56)
    for i, b in enumerate(fw.blocks):
        print("%-4d %-18s 0x%08X 0x%08X 0x%08X" %
              (i, b["name"], b["offset"], b["length"], b["flags"]))


def cmd_info(fw):
    print("File size     : %d (0x%X)" % (fw.size, fw.size))
    print("Declared size : %d (0x%X)" % (fw.decl_size, fw.decl_size))
    print("Chip model    : %s" % fw.chip)
    print("Header CRC16  : stored 0x%04X  (algorithm per vendor; this tool does not rely on this field)" %
          fw.hdr_crc_stored)
    print("TOC block count : %d (outer record table, encrypted undecoded)" % fw.block_count)
    print("Inner manifest  : %d parseable partitions" % len(fw.blocks))


def cmd_upgrade(fw, args):
    if args.transport == "ble":
        tp = BleTransport(args.target, write_uuid=args.write_uuid,
                          notify_uuid=args.notify_uuid, mtu=args.mtu)
    elif args.transport == "uart":
        tp = UartTransport(args.port, args.baud)
    else:
        print("Unknown transport: %s (choose ble/uart)" % args.transport)
        return 2
    if not fw.blocks:
        print("Error: no partitions parsed, cannot upgrade")
        return 2
    OtaSession(fw, tp, mtu=args.mtu).run()
    return 0


def main():
    ap = argparse.ArgumentParser(description="SincoOTA firmware upgrade PC adapter script")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n, h in [("list-blocks", "List partitions in firmware"), ("info", "Firmware header info")]:
        p = sub.add_parser(n, help=h)
        p.add_argument("file")
    p = sub.add_parser("upgrade", help="Run PC-side upgrade (needs real device)")
    p.add_argument("file")
    p.add_argument("--transport", default="ble", choices=["ble", "uart"])
    p.add_argument("--target", default="", help="BLE: device name or MAC")
    p.add_argument("--port", default="COM3", help="UART: COM port")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--mtu", type=int, default=244)
    p.add_argument("--write-uuid", default=None, help="BLE write characteristic UUID (override default)")
    p.add_argument("--notify-uuid", default=None, help="BLE notify characteristic UUID (override default)")
    args = ap.parse_args()
    if not os.path.isfile(args.file):
        print("File does not exist:", args.file)
        return 2
    fw = Firmware(args.file)
    if args.cmd == "list-blocks":
        cmd_list_blocks(fw)
    elif args.cmd == "info":
        cmd_info(fw)
    elif args.cmd == "upgrade":
        return cmd_upgrade(fw, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
