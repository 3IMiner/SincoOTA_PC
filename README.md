# SincoOTA · PC Upgrade Adapter

> Ports Sinco's Android-only Bluetooth firmware updater (built on the Jieli RCSP OTA SDK) to Windows PC, replaying the exact OTA sequence over **BLE** (`bleak`) or **UART** (`pyserial`). Offline `.fwsc` parsing, with both a CLI and a tkinter GUI.

## Background

SincoOTA is the official Android firmware-update app for Sinco music gear (SMC-Mixer / SMC-PAD / FootCtrl / VMX8 and 15+ other devices), built on the **Jieli official RCSP OTA SDK** (`com.jieli.jl_bt_ota` v1.9.2). It only runs on Android + BLE.

This project reverse-engineers the SDK and firmware, then replays the same "firmware upgrade sequence" on a PC using `bleak` / `pyserial` **1:1** — command opcodes, frame format, and payloads all match the official behavior, without cracking any encryption or instruction set.

### Target device profile (SMC-Mixer as example)

| Item | Value |
|---|---|
| Product | Sinco **SMC-Mixer** (MIDI mixer / controller) |
| MCU | Jieli **AC636N** (BLE audio SoC; firmware header `chip=AC636N`) |
| Firmware container | `.fwsc` (Jieli private container: 16B header + plaintext inner manifest + 7 partitions) |
| BLE advertising name | `SMC-Mixer` |
| Native upgrade channels | **UART / BLE / SD / USB / EDR** (confirmed by firmware partition names) |

> SincoOTA is not SMC-Mixer-only — `FilterDeviceKt.filterDeviceMap` registers 15+ sibling devices by advertising name (SMC-PAD / SMARTKEY25 / IMPULSE-R / MAESTROCTL / FootCtrlPlus / VMX8 / VMP16 / STARRYPAD MINI / OxyGen-25 / TurnerPro / WPTP-2 / RJMICRO25 / FS-1 / SMARTPAD / SMARTCON). This tool should cover the whole product line in theory, but only SMC-Mixer has been profiled on real hardware.

## RCSP frame wire format (calibrated, authoritative)

Recovered from the SDK's `RcspParser.smali` / `BasePacket.smali` / `JL_Constant.smali` disassembly; this is the authoritative basis for `sinco_ota_adapter.py`:

```
FE DC BA | HDR(1) | OP(1) | LEN(2, big-endian) | PARAM(LEN) | EF(1)
```

- Prefix `FE DC BA`; **HDR** = `(type<<7) | (hasResponse<<6)` (type=1 command / 0 response, hasResponse=1 expects ACK)
- **LEN** = byte count of the following `PARAM` (big-endian uint16; **excludes** prefix/HDR/OP/LEN/EF)
- **No in-frame CRC** (reliability relies on the BLE link layer) — the biggest difference from the "RCSP-with-CRC" versions floating around the web
- **Data phase uses a device-pull model**: the device actively sends `0xE5 [offset(4BE)][len(2BE)]` to *request* a block; the PC replies with a `0xE5` **response frame** `[status=0][sn][raw firmware bytes]`

### Upgrade sequence (verified command flow)

| Step | Action | Opcode | Dir | Notes |
|------|--------|--------|-----|-------|
| 4 | Get device info | `0x03` | →dev | `[mask(4BE)=FFFFFFFF][platform(1)]` |
| 5 | Get device MD5 | `0xD4` | →dev | no payload |
| 6 | Read upgrade flag | `0xE1` | →dev | resp `[offset(4BE)][len(2BE)]` |
| 7 | Firmware compatibility query | `0xE2` | →dev | echo back the firmware bytes at `[offset,len]` from step 6 |
| 8 | Notify total size | `0xE8` | →dev | `[contentSize(4BE)]` |
| 9 | Enter OTA mode | `0xE3` | →dev | no payload |
| 10 | Negotiate MTU | `0xD1` | →dev | `[mtu(2BE)]` (for SPP; optional over BLE) |
| 11 | **Data phase (device pull)** | `0xE5` | **dev→PC** | `[offset][len]` requests a block |
| 11b | Send block data | `0xE5` | **PC→dev** | resp `[status=0][sn][firmware bytes]` |
| 12 | Query result | `0xE6` | →dev | resp status |
| 13 | Exit OTA | `0xE4` | →dev | no payload |
| 14 | Reboot device | `0xE7` | →dev | `[param(1)]`, `0`=reboot |

> The `offset/len` the device requests are **offsets/lengths into the whole `.fwsc` package**, so the data phase does not need a partition table at all — the partition table is only for human reading / export.

## Directory layout

```
SincoOTA/
├── sinco_ota_adapter.py   # Core: RCSP protocol + BLE/UART transport + OTA session (with CLI)
├── sinco_gui.py           # tkinter GUI: pick firmware → parse → choose channel → upgrade → live log → export partitions
├── jlufw_tool.py          # .fwsc offline parser library + CLI (16B LFSR header deobfuscation / partition export)
├── jlufw_toolbox.py       # Firmware toolbox GUI (built on jlufw_tool)
├── SincoOTA_PC.spec       # PyInstaller single-file build spec
├── JLUFW_Toolbox.bat      # Toolbox one-click launcher (Windows)
└── README.md  LICENSE  .gitignore  .gitattributes
```

> The repository intentionally contains **only the runnable tool**. Build artifacts, proprietary binaries, the extended analysis docs (`docs/`), and the reverse-engineering scripts (`research/`) are kept **outside** the repository in a local `SincoOTA_extras/` folder alongside it (not versioned). See `.gitignore` for the excludes: `dist/ build/ build_sinco/ _build/ __pycache__/`, `_unpack/ smali2/`, `*.fwsc *.apk *.exe *.png`.

## Dependencies

```bash
pip install pyserial bleak
# GUI needs tkinter (ships with the Python standard library; included in the Windows installer, or pip install tk)
```

- Python 3.10+ (verified on 3.12 / 3.14).

## Usage

### CLI (no hardware needed — verify firmware parsing first)

```bash
# Show firmware header info
python sinco_ota_adapter.py info SMC-Mixer_012.fwsc

# List the 7 partitions (uart/ble/sd/usb/edr/...)
python sinco_ota_adapter.py list-blocks SMC-Mixer_012.fwsc

# BLE upgrade (device advertises JL OTA service; PC needs Bluetooth)
python sinco_ota_adapter.py upgrade SMC-Mixer_012.fwsc --transport ble --target "JL_XXXX"

# UART serial upgrade (device must expose a TTL serial port)
python sinco_ota_adapter.py upgrade SMC-Mixer_012.fwsc --transport uart --port COM3 --baud 115200
```

### GUI

```bash
python sinco_gui.py
```

Pick firmware → auto-parse → choose BLE / serial channel → start upgrade → live log; export all partitions with one click.

### Firmware toolbox (offline parsing / partition export)

```bash
python jlufw_tool.py --help
# or just double-click JLUFW_Toolbox.bat
```

## Build a standalone exe

```bash
pip install pyinstaller
pyinstaller SincoOTA_PC.spec
# equivalent to:
pyinstaller -F -w --hidden-import serial --hidden-import serial.tools.list_ports \
  --hidden-import bleak --hidden-import asyncio sinco_gui.py
```

Output: `dist/SincoOTA_PC.exe` (single file, ~15 MB; confirmed to bundle `serial` / `bleak` / `asyncio` / `tkinter` / `sinco_ota_adapter`).

## Known limitations / still needs real-device validation

1. **Auth `RcspAuth`**: the official app sets `useAuthDevice=true` (mandatory); the signing algorithm lives in `libjl_ota_auth.so` (ARM only, no PC build). Full BLE upgrade needs this algorithm reproduced on PC (reverse the so / ARM emulation via box64·qemu / or first check whether the UART channel skips auth).
2. **MTU**: the real app uses `mtu=20` and does not negotiate ATT MTU; send payloads in 20-byte chunks.
3. **BLE UUID**: defaults to the Jieli standard `0000AE00/0000AE01/0000AE02`; override with `--write-uuid/--notify-uuid`.
4. **Serial frame**: the UART channel assumes the same frame format as BLE (no extra `AA55` wrapper), pending real-device calibration.
5. **USB upgrade mode**: a normal USB connection is an audio/MIDI composite device (**no COM port**); real USB upgrade is triggered by the hardware bootloader (hold the main button while plugging in USB).

## Legal disclaimer

This project is for **interoperability research / personal device firmware backup and upgrade**. The code replays the protocol by reproducing SDK behavior and **contains no proprietary binaries or key material from the reverse-engineered party**. The repository **does not include** the original `SincoOTA.apk` or any `.fwsc` firmware images (proprietary binaries — obtain them yourself from a legally owned device / official channel). Make sure you have the legal right to the device before upgrading with this tool; use at your own risk.

## Author

Created by **3IMiner** in collaboration with an AI assistant.

## License

[MIT](LICENSE) — see the LICENSE file.
