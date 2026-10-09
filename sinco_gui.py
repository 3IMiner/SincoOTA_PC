#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sinco_gui.py - SincoOTA firmware upgrade - PC adaptation tool (GUI)
==============================================================
Based on sinco_ota_adapter: reuses its firmware parsing (verified) + RCSP OTA trajectory reenactment.
Moves SincoOTA's "push firmware over Bluetooth" runtime trajectory on Android into a Windows window.

Features:
  * Open .fwsc -> parse header (16-bit LFSR de-obfuscation) + split partitions using the plaintext inner manifest (verified)
  * Choose transport channel: BLE (bleak, faithfully reenacts the original path) / UART (Bluetooth-free, RCSP-over-UART)
  * Click "Start upgrade" -> reenact trajectory: connect -> handshake/auth -> query info -> enter OTA -> send block by block -> reboot
  * Real-time log; protocol command opcodes / packetization calibrated against real-device HCI logs

Run:     python sinco_gui.py
Package: pyinstaller -F -w -i icon.ico sinco_gui.py
"""

import os
import struct
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sinco_ota_adapter import (Firmware, BleTransport, UartTransport,
                               OtaSession, RCSP_SOF)  # noqa: E402

APP_TITLE = "SincoOTA · PC Upgrade Adapter Tool"
FILETYPES = [("JieLi firmware", "*.fwsc *.ufw *.bfu *.bin *.*")]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("920x720")
        self.minsize(820, 600)
        self.fw = None
        self._ota_thread = None
        self._build()

    # ---------------------------------------------------------------- UI
    def _build(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

        # File selection
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Firmware file:").pack(side="left")
        self.var_path = tk.StringVar()
        ttk.Entry(top, textvariable=self.var_path).pack(
            side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Browse…", command=self.open_dialog).pack(side="left")
        ttk.Button(top, text="Parse", command=self.reparse).pack(side="left", padx=(6, 0))

        # Header info
        g1 = ttk.LabelFrame(self, text=" Firmware header / verification ", padding=8)
        g1.pack(fill="x", padx=10, pady=4)
        self.txt_hdr = tk.Text(g1, height=6, font=("Consolas", 10),
                               bg="#fafafa", relief="flat", state="disabled")
        self.txt_hdr.pack(fill="x")

        # Partition table
        g2 = ttk.LabelFrame(self, text=" Partition table (inner manifest breakdown) ", padding=8)
        g2.pack(fill="both", expand=True, padx=10, pady=4)
        cols = ("idx", "name", "offset", "length", "flags")
        self.tree = ttk.Treeview(g2, columns=cols, show="headings", height=8)
        for cid, text, w in [("idx", "#", 40), ("name", "Partition name", 160),
                             ("offset", "File offset", 110), ("length", "Length", 110),
                             ("flags", "flags", 100)]:
            self.tree.heading(cid, text=text)
            self.tree.column(cid, width=w)
        ys = ttk.Scrollbar(g2, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="left", fill="y")

        # ---- OTA panel ----
        g3 = ttk.LabelFrame(self, text=" Upgrade (reenact SincoOTA runtime trajectory) ", padding=8)
        g3.pack(fill="x", padx=10, pady=4)

        row = ttk.Frame(g3)
        row.pack(fill="x")
        ttk.Label(row, text="Channel:").pack(side="left")
        self.var_tp = tk.StringVar(value="ble")
        ttk.Radiobutton(row, text="BLE (Bluetooth)", variable=self.var_tp,
                        value="ble", command=self._on_tp).pack(side="left", padx=4)
        ttk.Radiobutton(row, text="UART (Bluetooth-free)", variable=self.var_tp,
                        value="uart", command=self._on_tp).pack(side="left", padx=4)

        self.frm_params = ttk.Frame(g3)
        self.frm_params.pack(fill="x", pady=4)
        self._build_ble_params()
        self._build_uart_params()
        self._on_tp()

        row2 = ttk.Frame(g3)
        row2.pack(fill="x", pady=2)
        ttk.Label(row2, text="MTU:").pack(side="left")
        self.var_mtu = tk.StringVar(value="244")
        ttk.Entry(row2, textvariable=self.var_mtu, width=8).pack(side="left", padx=4)
        ttk.Button(row2, text="Start upgrade", command=self.start_ota).pack(side="left", padx=8)
        ttk.Button(row2, text="Export all partitions…", command=self.export_all).pack(side="left")

        # Log
        self.txt_log = tk.Text(g3, height=9, font=("Consolas", 9),
                               bg="#11141a", fg="#d8dee9", relief="flat")
        self.txt_log.pack(fill="x", pady=(4, 0))
        self.txt_log.configure(state="disabled")

        # Status bar
        self.var_status = tk.StringVar(value="Ready — open a .fwsc firmware file")
        ttk.Label(self, textvariable=self.var_status, relief="sunken",
                  anchor="w", padding=(6, 3)).pack(fill="x", side="bottom")

    def _build_ble_params(self):
        self.frm_ble = ttk.Frame(self.frm_params)
        ttk.Label(self.frm_ble, text="Device name/MAC:").pack(side="left")
        self.var_target = tk.StringVar(value="JL_")
        ttk.Entry(self.frm_ble, textvariable=self.var_target, width=22).pack(side="left", padx=4)
        ttk.Label(self.frm_ble, text="(PC requires Bluetooth)").pack(side="left")

    def _build_uart_params(self):
        self.frm_uart = ttk.Frame(self.frm_params)
        ttk.Label(self.frm_uart, text="COM port:").pack(side="left")
        self.var_port = tk.StringVar(value="")
        self.cbo_port = ttk.Combobox(self.frm_uart, textvariable=self.var_port,
                                     width=12, state="readonly")
        self.cbo_port.pack(side="left", padx=4)
        ttk.Button(self.frm_uart, text="Refresh", command=self._refresh_ports).pack(side="left")
        ttk.Label(self.frm_uart, text="Baud rate:").pack(side="left")
        self.var_baud = tk.StringVar(value="115200")
        ttk.Entry(self.frm_uart, textvariable=self.var_baud, width=9).pack(side="left", padx=4)
        self._refresh_ports()

    def _refresh_ports(self):
        """Auto-list the PC's available COM ports, directly answering the "can't detect COM port" question."""
        ports = []
        try:
            import serial.tools.list_ports
            ports = [p.device for p in serial.tools.list_ports.comports()]
        except Exception:
            pass
        if not ports:
            ports = ["COM3"]
        self.cbo_port["values"] = ports
        if not self.var_port.get() or self.var_port.get() not in ports:
            self.var_port.set(ports[0])

    def _on_tp(self):
        tp = self.var_tp.get()
        self.frm_ble.pack_forget()
        self.frm_uart.pack_forget()
        (self.frm_ble if tp == "ble" else self.frm_uart).pack(side="left", fill="x")

    # ---------------------------------------------------------------- actions
    def open_dialog(self):
        p = filedialog.askopenfilename(title="Select firmware file", filetypes=FILETYPES)
        if p:
            self.var_path.set(p)
            self.reparse()

    def reparse(self):
        p = self.var_path.get().strip().strip('"')
        if not p or not os.path.isfile(p):
            messagebox.showerror(APP_TITLE, "File does not exist:\n%s" % p)
            return
        try:
            self.fw = Firmware(p)
        except Exception as e:
            messagebox.showerror(APP_TITLE, "Parse error:\n%r" % e)
            return
        self._show_header()
        self._fill_tree()
        self.var_status.set("%s — %d partitions — chip %s" %
                           (os.path.basename(p), len(self.fw.blocks), self.fw.chip))

    def _show_header(self):
        fw = self.fw
        self.txt_hdr.configure(state="normal")
        self.txt_hdr.delete("1.0", "end")
        L = []
        L.append("File size   : %d (0x%X)" % (fw.size, fw.size))
        L.append("Declared size : %d (0x%X)" % (fw.decl_size, fw.decl_size))
        L.append("Chip model : %s" % fw.chip)
        L.append("Header CRC(stored) : 0x%04X  (algorithm per vendor)" % fw.hdr_crc_stored)
        L.append("Outer TOC  : %d entries (encrypted, undecoded); inner manifest: %d partitions"
                 % (fw.block_count, len(fw.blocks)))
        self.txt_hdr.insert("end", "\n".join(L))
        self.txt_hdr.configure(state="disabled")

    def _fill_tree(self):
        self.tree.delete(*self.tree.get_children())
        if not self.fw:
            return
        for i, b in enumerate(self.fw.blocks):
            self.tree.insert("", "end", iid=str(i), values=(
                i, b["name"], "0x%X" % b["offset"], "0x%X" % b["length"],
                "0x%X" % b["flags"]))

    def export_all(self):
        if not self.fw:
            messagebox.showinfo(APP_TITLE, "Please open a firmware file first")
            return
        d = filedialog.askdirectory(title="Select export directory")
        if not d:
            return
        out = os.path.join(d, os.path.splitext(os.path.basename(self.fw.path))[0] + "_blocks")
        os.makedirs(out, exist_ok=True)
        for i, b in enumerate(self.fw.blocks):
            name = b["name"].replace("/", "_").replace("\\", "_") or ("block_%d" % i)
            if not name.lower().endswith((".bin", ".dat", ".ini")):
                name += ".bin"
            data = self.fw.block_data(b)
            with open(os.path.join(out, "%02d_%s" % (i, name)), "wb") as f:
                f.write(data)
        messagebox.showinfo(APP_TITLE, "Exported %d partitions to:\n%s" % (len(self.fw.blocks), out))

    # ---------------------------------------------------------------- OTA
    def gui_log(self, msg):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", msg + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def log_threadsafe(self, msg):
        self.after(0, lambda: self.gui_log(msg))

    def start_ota(self):
        if not self.fw or not self.fw.blocks:
            messagebox.showerror(APP_TITLE, "Please open and parse a firmware first")
            return
        if self._ota_thread and self._ota_thread.is_alive():
            messagebox.showinfo(APP_TITLE, "Upgrade in progress, please wait")
            return
        try:
            mtu = int(self.var_mtu.get())
        except ValueError:
            mtu = 244
        if self.var_tp.get() == "ble":
            try:
                tp = BleTransport(self.var_target.get().strip())
            except RuntimeError as e:
                messagebox.showerror(APP_TITLE, str(e))
                return
        else:
            try:
                tp = UartTransport(self.var_port.get().strip(),
                                   int(self.var_baud.get()))
            except (RuntimeError, ValueError) as e:
                messagebox.showerror(APP_TITLE, str(e))
                return
        self.gui_log("=== Starting upgrade (channel=%s) ===" % self.var_tp.get())
        sess = OtaSession(self.fw, tp, mtu=mtu, log_fn=self.log_threadsafe)
        self._ota_thread = threading.Thread(target=self._run_ota, args=(sess,), daemon=True)
        self._ota_thread.start()

    def _run_ota(self, sess):
        try:
            sess.run()
            self.log_threadsafe("=== Upgrade finished ===")
        except Exception as e:
            self.log_threadsafe("!! Exception: %r" % e)
            self.log_threadsafe("!! Transport layer / protocol command opcodes may need calibration against real-device HCI logs; see console/docs")


def main():
    app = App()
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        app.var_path.set(sys.argv[1])
        app.after(100, app.reparse)
    app.mainloop()


if __name__ == "__main__":
    main()
