#!/usr/bin/env python3
"""Fabrique les icônes de Windows et de macOS à partir des images de assets/icons.

Sortie : assets/windows/netbuster.ico, assets/windows/netbuster.rc et assets/macos/netbuster.icns.
Pour refaire netbuster.res ensuite : zig rc /fo netbuster.res netbuster.rc (depuis assets/windows).
"""
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent
ICONS = ROOT / "icons"


def png(size):
    return (ICONS / f"netbuster-{size}.png").read_bytes()


def make_ico(sizes):
    entries, images = b"", b""
    offset = 6 + 16 * len(sizes)
    for s in sizes:
        data = png(s)
        # 256 s'écrit 0 dans ce format.
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), offset)
        images += data
        offset += len(data)
    return struct.pack("<HHH", 0, 1, len(sizes)) + entries + images


def make_icns(types):
    body = b""
    for kind, size in types:
        data = png(size)
        body += kind + struct.pack(">I", len(data) + 8) + data
    return b"icns" + struct.pack(">I", len(body) + 8) + body


RC = """1 ICON "netbuster.ico"

1 VERSIONINFO
FILEVERSION 0,1,0,0
PRODUCTVERSION 0,1,0,0
FILEOS 0x40004
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040C04B0"
    BEGIN
      VALUE "CompanyName", "Serge Eric Hotegni"
      VALUE "FileDescription", "NetBuster"
      VALUE "FileVersion", "0.1.0"
      VALUE "InternalName", "netbuster"
      VALUE "OriginalFilename", "netbuster.exe"
      VALUE "ProductName", "NetBuster"
      VALUE "ProductVersion", "0.1.0"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x040C, 1200
  END
END
"""

win = ROOT / "windows"
mac = ROOT / "macos"
win.mkdir(exist_ok=True)
mac.mkdir(exist_ok=True)
(win / "netbuster.ico").write_bytes(make_ico([16, 24, 32, 48, 64, 128, 256]))
(win / "netbuster.rc").write_text(RC, encoding="utf-8")
(mac / "netbuster.icns").write_bytes(make_icns([(b"ic11", 32), (b"ic12", 64), (b"ic07", 128), (b"ic08", 256), (b"ic13", 256), (b"ic09", 512), (b"ic14", 512)]))
