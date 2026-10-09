#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JLUFW firmware toolbox - Windows desktop program (tkinter, zero third-party dependencies)
=========================================================================================
JieLi JLUFW upgrade-package offline parsing / verification / decryption / export tool
Algorithm reverse-engineered from libjl_ota_auth.so inside SincoOTA.apk, verified via round-trip on synthetic firmware

Run:     python jlufw_toolbox.py        (double-clicking jlufw_toolbox.bat also works)
Package: pyinstaller -F -w -i icon.ico jlufw_toolbox.py
"""

import os
import struct
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jlufw_tool import Firmware, _hexprint  # noqa: E402

APP_TITLE = "JLUFW Firmware Toolbox v2.0"
FILETYPES = [("JieLi firmware/All files", "*.ufw *.bfu *.bin *.*")]

C_OK, C_BAD, C_WARN = "#1a7f37", "#c62828", "#b26a00"


class HexView(tk.Toplevel):
    """Block data hex viewer"""

    def __init__(self, master, title, data, base_off, note=""):
        super().__init__(master)
        self.title(f"{title} — Hex view ({len(data)} bytes)")
        self.geometry("880x560")
        txt = tk.Text(self, font=("Consolas", 10), bg="#11141a", fg="#d8dee9",
                      insertbackground="#d8dee9", wrap="none")
        ysb = ttk.Scrollbar(self, orient="vertical", command=txt.yview)
        xsb = ttk.Scrollbar(self, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        txt.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hexs = " ".join(f"{c:02x}" for c in chunk)
            pad = "   ".join(hexs[j:j + 8] for j in (0, 17)) if False else hexs
            asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
            lines.append(f"{base_off + i:08X}  {hexs:<47}  |{asc}|")
        if note:
            lines.insert(0, f"# {note}\n")
        txt.insert("1.0", "\n".join(lines) or "(empty)")
        txt.configure(state="disabled")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x680")
        self.minsize(820, 560)
        self.fw = None
        self._build()

    # ------------------------------------------------------------ UI
    def _build(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Firmware file:").pack(side="left")
        self.var_path = tk.StringVar()
        ttk.Entry(top, textvariable=self.var_path).pack(
            side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Browse…", command=self.open_dialog).pack(side="left")
        ttk.Button(top, text="Re-parse", command=self.reparse).pack(
            side="left", padx=(6, 0))

        # ---- Summary ----
        grp = ttk.LabelFrame(self, text=" Firmware header & verification ", padding=8)
        grp.pack(fill="x", padx=10, pady=(4, 4))
        self.txt_sum = tk.Text(grp, height=9, font=("Consolas", 10),
                               bg="#fafafa", relief="flat", state="disabled")
        self.txt_sum.pack(fill="x")

        # ---- Block table ----
        grp2 = ttk.LabelFrame(self, text=" Block record table ", padding=8)
        grp2.pack(fill="both", expand=True, padx=10, pady=4)
        cols = ("idx", "type", "name", "offset", "length", "enc", "declen", "crc")
        self.tree = ttk.Treeview(grp2, columns=cols, show="headings", height=9)
        heads = [("idx", "#", 40, "e"), ("type", "Type", 60, "e"),
                 ("name", "Block name", 150, "w"), ("offset", "File offset", 100, "e"),
                 ("length", "Length", 100, "e"), ("enc", "Enc region @block", 100, "e"),
                 ("declen", "Enc length", 90, "e"), ("crc", "Data CRC16", 110, "e")]
        for cid, text, w, anch in heads:
            self.tree.heading(cid, text=text)
            self.tree.column(cid, width=w, anchor=anch)
        ysb = ttk.Scrollbar(grp2, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="left", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.view_block())

        # ---- Action buttons ----
        btns = ttk.Frame(self, padding=(10, 2))
        btns.pack(fill="x")
        ttk.Button(btns, text="Hex view selected block", command=self.view_block).pack(side="left")
        ttk.Button(btns, text="Export selected block…", command=self.export_selected).pack(side="left", padx=6)
        ttk.Button(btns, text="Export all blocks…", command=self.export_all).pack(side="left")
        ttk.Button(btns, text="Export firmware header (de-obfuscated)…", command=self.export_header).pack(side="left", padx=6)

        # ---- Status bar ----
        self.var_status = tk.StringVar(value="Ready — open a .ufw/.bfu firmware file to start")
        sb = ttk.Label(self, textvariable=self.var_status, relief="sunken",
                       anchor="w", padding=(6, 3))
        sb.pack(fill="x", side="bottom")

    # ------------------------------------------------------------ actions
    def open_dialog(self):
        p = filedialog.askopenfilename(title="Select firmware file", filetypes=FILETYPES)
        if p:
            self.var_path.set(p)
            self.reparse()

    def reparse(self):
        p = self.var_path.get().strip().strip('"')
        if not p:
            return
        if not os.path.isfile(p):
            messagebox.showerror(APP_TITLE, f"File does not exist:\n{p}")
            return
        try:
            self.fw = Firmware(p)
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Parse error:\n{e!r}")
            return
        self._show_summary()
        self._fill_tree()
        n = len(self.fw.blocks)
        ok = "verification passed" if self.fw.overall_ok() else "anomalies found, see summary"
        self.var_status.set(f"{os.path.basename(p)} — {n} blocks — {ok}")

    def _show_summary(self):
        fw = self.fw
        self.txt_sum.configure(state="normal")
        self.txt_sum.delete("1.0", "end")

        def w(s, tag=None):
            self.txt_sum.insert("end", s, tag or ())

        w(f"File size: {fw.size} bytes (0x{fw.size:X})    Declared length: "
          f"{fw.decl_file_size} (0x{fw.decl_file_size:X})\n")
        if fw.hdr is not None:
            w(f"Header CRC16 : ", ())
            self._tag_val(fw.hdr_crc_ok,
                          f"{fw.hdr_crc_stored:#06x} / computed {fw.hdr_crc_calc:#06x}\n")
            w(f"Table CRC16 : ")
            self._tag_val(fw.tbl_crc_ok,
                          f"{fw.tbl_crc_stored:#06x} / computed {getattr(fw,'tbl_crc_calc',0):#06x}\n")
        if fw.tail is not None:
            w("tail.bin: ")
            self._tag_val(fw.tail_magic_ok, "magic 0x36659213+0x4273 ")
            self._tag_val(fw.tail_crc_ok, f"key block CRC ")
            if fw.key is not None:
                w(f"Decryption key key={fw.key:#06x} (auto-decrypt enabled)\n", ("ok",))
            else:
                w("Key derivation failed, encrypted blocks exported as-is\n", ("bad",))
        else:
            w("tail.bin: not found (no decryption key, encrypted blocks exported as-is)\n", ("warn",))
        for e in fw.errors:
            w(f"  ✗ {e}\n", ("bad",))
        for e in fw.warnings:
            w(f"  ⚠ {e}\n", ("warn",))
        if fw.overall_ok():
            w("✓ All checks passed\n", ("ok",))
        self.txt_sum.tag_configure("ok", foreground=C_OK)
        self.txt_sum.tag_configure("bad", foreground=C_BAD)
        self.txt_sum.tag_configure("warn", foreground=C_WARN)
        self.txt_sum.configure(state="disabled")

    def _tag_val(self, ok, text):
        self.txt_sum.insert("end", ("✓ " if ok else "✗ ") + text,
                            "ok" if ok else "bad")

    def _fill_tree(self):
        self.tree.delete(*self.tree.get_children())
        if not self.fw:
            return
        for b in self.fw.blocks:
            data = self.fw.raw[b["offset"]:b["offset"] + b["length"]]
            from jlufw_tool import crc16_ccitt
            crc = f"{crc16_ccitt(data):#06x}" if data else "-"
            enc = f"{b['enc_start']:#x} ({b['enc_len']:#x}B)" if b["enc_len"] else "-"
            mark = " 🔓" if b["enc_len"] and self.fw.key is not None else ""
            self.tree.insert("", "end", iid=str(b["index"]), values=(
                b["index"], f"{b['type']:#04x}", b["name"] + mark,
                f"{b['offset']:#x}", f"{b['length']:#x}", enc, crc))

    def _sel_block(self):
        if not self.fw:
            messagebox.showinfo(APP_TITLE, "Please open a firmware file first")
            return None
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "Please select a block in the table first")
            return None
        return self.fw.blocks[int(sel[0])]

    def view_block(self):
        b = self._sel_block()
        if not b:
            return
        data = self.fw.block_data(b)
        note = []
        if b["enc_len"]:
            note.append(f"Encrypted region at block offset 0x{b['enc_start']:X}, 0x{b['enc_len']:X} bytes"
                        + (" (auto-decrypted)" if self.fw.key is not None else " (no key, raw)"))
        note.append(f"type={b['type']} offset={b['offset']:#x} length={b['length']:#x}")
        HexView(self, b["name"], data, b["offset"], "; ".join(note))

    def export_selected(self):
        b = self._sel_block()
        if not b:
            return
        p = filedialog.asksaveasfilename(
            title="Export block", initialfile=b["name"] or f"block_{b['index']}.bin",
            defaultextension=".bin")
        if not p:
            return
        with open(p, "wb") as f:
            f.write(self.fw.block_data(b))
        self.var_status.set(f"Exported {b['name']} -> {p}")

    def export_all(self):
        if not self.fw:
            messagebox.showinfo(APP_TITLE, "Please open a firmware file first")
            return
        d = filedialog.askdirectory(title="Select export directory")
        if not d:
            return
        out = os.path.join(d, os.path.splitext(os.path.basename(self.fw.path))[0] + "_blocks")
        os.makedirs(out, exist_ok=True)
        for b in self.fw.blocks:
            safe = (b["name"].replace("/", "_").replace("\\", "_")
                    or f"block_{b['index']}")
            if not safe.lower().endswith((".bin", ".dat", ".ufw", ".bfu")):
                safe += ".bin"
            with open(os.path.join(out, f"{b['index']:02d}_{safe}"), "wb") as f:
                f.write(self.fw.block_data(b))
        self.var_status.set(f"Exported {len(self.fw.blocks)} blocks -> {out}")
        messagebox.showinfo(APP_TITLE, f"Exported {len(self.fw.blocks)} blocks to:\n{out}")

    def export_header(self):
        if not self.fw or self.fw.hdr is None:
            messagebox.showinfo(APP_TITLE, "Please open a firmware file first")
            return
        p = filedialog.asksaveasfilename(title="Export firmware header",
                                         initialfile="header_decoded.bin",
                                         defaultextension=".bin")
        if not p:
            return
        with open(p, "wb") as f:
            f.write(bytes(self.fw.hdr))
        self.var_status.set(f"Exported de-obfuscated firmware header -> {p}")


def main():
    app = App()
    # If a file path is given on the command line, open it directly
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        app.var_path.set(sys.argv[1])
        app.after(100, app.reparse)
    app.mainloop()


if __name__ == "__main__":
    main()
