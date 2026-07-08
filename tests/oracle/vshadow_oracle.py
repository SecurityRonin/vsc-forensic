#!/usr/bin/env python3
"""Tier-1 VSS oracle for vsc-core validation.

Enumerates the Volume Shadow Copy stores in a raw NTFS volume (or an E01
partition) using libvshadow (pyvshadow) — the independent reference tool that
vsc-core is validated against. Prints the ground truth (store count, GUID,
creation time, volume size) that the Rust integration test asserts on.

Requires: pyewf, pytsk3, pyvshadow (the libyal Python bindings).

Usage:
    # Enumerate every VSS store in every NTFS partition of an E01 disk image:
    python3 vshadow_oracle.py /path/to/PC-MUS-001.E01

    # Or point at an already-windowed raw NTFS volume + its byte offset:
    python3 vshadow_oracle.py --raw /path/to/disk.raw --offset 122683392

The confirmed Tier-1 oracle in this fleet is the Magnet Summit 2023 CTF image
`PC-MUS-001.E01` (issen/tests/data/magnet-summit-2023-ctf/), whose main NTFS
volume (part 6, byte offset 122683392) carries exactly one shadow copy:
    store[0] id=1afc8871-8c76-11ed-8c4d-f894c2dfe804
             created=2023-01-04 21:38:00.825426 (UTC)
             volume_size=255136931328
"""
import argparse
import sys

import pyewf
import pytsk3
import pyvshadow


class _EwfImg(pytsk3.Img_Info):
    def __init__(self, handle):
        self._handle = handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._handle.close()

    def read(self, offset, size):
        self._handle.seek(offset)
        return self._handle.read(size)

    def get_size(self):
        return self._handle.get_media_size()


def _window(reader, base, size):
    """A file-object view of [base, base+size) over a seekable reader."""

    class Window:
        def __init__(self):
            self.pos = 0

        def read(self, n=None):
            reader.seek(base + self.pos)
            remaining = size - self.pos
            take = remaining if n is None else min(n, remaining)
            data = reader.read(take)
            self.pos += len(data)
            return data

        def seek(self, offset, whence=0):
            if whence == 0:
                self.pos = offset
            elif whence == 1:
                self.pos += offset
            else:
                self.pos = size + offset
            return self.pos

        def tell(self):
            return self.pos

        def get_size(self):
            return size

    return Window()


def _dump_stores(reader, base, size, label):
    try:
        vol = pyvshadow.volume()
        vol.open_file_object(_window(reader, base, size))
    except Exception as exc:  # noqa: BLE001 — report, do not raise
        print("  %s @%d: no VSS (%s)" % (label, base, str(exc).split(":")[0]))
        return 0
    n = vol.number_of_stores
    print("  %s @%d: %d VSS store(s)" % (label, base, n))
    for i in range(n):
        st = vol.get_store(i)
        print(
            "    store[%d] id=%s created=%s volume_size=%d"
            % (i, st.get_identifier(), st.get_creation_time(), st.get_volume_size())
        )
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", help="E01 disk image (or raw volume with --raw)")
    ap.add_argument("--raw", action="store_true", help="image is a raw NTFS volume")
    ap.add_argument("--offset", type=int, default=0, help="volume byte offset (raw)")
    args = ap.parse_args()

    if args.raw:
        f = open(args.image, "rb")
        f.seek(0, 2)
        size = f.tell() - args.offset
        f.seek(0)
        _dump_stores(f, args.offset, size, "raw")
        return

    handle = pyewf.handle()
    handle.open(pyewf.glob(args.image))
    vol = pytsk3.Volume_Info(_EwfImg(handle))
    total = 0
    for p in vol:
        base = p.start * 512
        size = p.len * 512
        if size < 10 * 1024 * 1024:
            continue
        handle.seek(base)
        if handle.read(16)[3:11] != b"NTFS    ":
            continue
        total += _dump_stores(handle, base, size, "part %d" % p.addr)
    if total == 0:
        print("  (no VSS stores in any NTFS partition)")
        sys.exit(1)


if __name__ == "__main__":
    main()
