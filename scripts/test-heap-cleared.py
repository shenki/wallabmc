#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Tenstorrent USA, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check that the mbedTLS heap is cleared when the BMC reboots.

Every HTTPS connection has a parsed copy of the HTTPS key in the mbedTLS
heap. Where the heap is in DTCM it is in a NOLOAD section, which early boot
doesn't zero, so the copies survive a warm reset until
mbedtls_memory_buffer_alloc_init() clears the heap.

This opens some HTTPS connections, then with OpenOCD dumps the heap:

  1. while the BMC is running, with the connections open
  2. halted at the reset vector, after a reset
  3. on entry to mbedtls_memory_buffer_alloc_init()
  4. when it has returned

It passes if dump 1 has the HTTPS public key in it (so the test can see key
material), dump 3 is either the same as dump 1 or all zeroes (nothing used
the heap before it was initialised), and dump 4 has no copy of the key and
nothing but the allocator's first block header.

The board is reset. It must be running the build in the build directory:
the addresses come from its zephyr.elf. Needs an STM32 board with a debug
probe OpenOCD supports.

Usage: test-heap-cleared.py [-s PROBE_SERIAL] [-n CONNECTIONS] BUILD_DIR IP
"""

import argparse
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HEADER_SIZE = 32  # sizeof(memory_header) in memory_buffer_alloc.c


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def app_dir(build_dir):
    """The application image's build directory, with or without sysbuild."""
    domains = build_dir / "domains.yaml"
    if not domains.exists():
        return build_dir
    m = re.search(r"^default: *(\S+)", domains.read_text(), re.MULTILINE)
    return build_dir / m.group(1)


def cache_value(cache, name):
    m = re.search(rf"^{name}:[A-Z]+=(.*)$", cache, re.MULTILINE)
    if not m or not m.group(1):
        fail(f"{name} is not in CMakeCache.txt")
    return m.group(1)


def find_addresses(nm, objdump, elf):
    """The heap's address and size, the init function, and where it returns to."""
    syms = subprocess.run([nm, "-S", elf], check=True, capture_output=True, text=True).stdout
    m = re.search(r"^([0-9a-f]+) ([0-9a-f]+) \w _mbedtls_heap$", syms, re.MULTILINE)
    if not m:
        fail("no _mbedtls_heap in the image, is CONFIG_MBEDTLS_ENABLE_HEAP set?")
    heap, size = int(m.group(1), 16), int(m.group(2), 16)
    m = re.search(r"^([0-9a-f]+) [0-9a-f]+ \w mbedtls_memory_buffer_alloc_init$", syms,
                  re.MULTILINE)
    if not m:
        fail("no mbedtls_memory_buffer_alloc_init in the image")
    init = int(m.group(1), 16)

    # The instruction after the one call to it
    dis = subprocess.run([objdump, "-d", elf], check=True, capture_output=True, text=True).stdout
    lines = dis.splitlines()
    calls = [i for i, ln in enumerate(lines)
             if re.search(r"\tbl\t[0-9a-f]+ <mbedtls_memory_buffer_alloc_init>", ln)]
    if len(calls) != 1:
        fail(f"expected one call to mbedtls_memory_buffer_alloc_init, found {len(calls)}")
    m = re.match(r" *([0-9a-f]+):", lines[calls[0] + 1])
    if not m:
        fail("could not find the instruction after the call")
    return heap, size, init, int(m.group(1), 16)


def public_key_x(der):
    """The X coordinate of the P-256 public key in a DER certificate."""
    i = der.find(b"\x03\x42\x00\x04")  # BIT STRING, 66 bytes, uncompressed point
    if i < 0:
        fail("the HTTPS certificate's key is not P-256")
    return der[i + 4:i + 36]


def open_connections(ip, count):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conns, cert = [], None
    for _ in range(count):
        s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=30))
        s.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
        s.recv(4096)
        cert = s.getpeercert(binary_form=True)
        conns.append(s)
        time.sleep(0.5)
    return conns, cert


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("build_dir", type=Path, help="the build that is running on the board")
    ap.add_argument("ip", help="the board's address")
    ap.add_argument("-s", "--serial", help="debug probe serial number, if more than one is attached")
    ap.add_argument("-n", "--connections", type=int, default=3,
                    help="HTTPS connections to open (default 3)")
    ap.add_argument("--keep", action="store_true", help="keep the dumps and the OpenOCD log")
    args = ap.parse_args()

    app = app_dir(args.build_dir)
    cache = (app / "CMakeCache.txt").read_text()
    heap, size, init, ret = find_addresses(cache_value(cache, "CMAKE_NM"),
                                           cache_value(cache, "CMAKE_OBJDUMP"),
                                           app / "zephyr" / "zephyr.elf")
    openocd = Path(cache_value(cache, "OPENOCD"))
    board_cfg = Path(cache_value(cache, "BOARD_DIR")) / "support" / "openocd.cfg"
    print(f"heap {size} B at {heap:#x}, mbedtls_memory_buffer_alloc_init at {init:#x}, "
          f"returns to {ret:#x}")

    conns, cert = open_connections(args.ip, args.connections)
    key_x = public_key_x(cert)
    print(f"{len(conns)} HTTPS connections open")

    tmp = Path(tempfile.mkdtemp(prefix="heap-cleared-"))
    names = ["1-running", "2-reset", "3-init-entry", "4-init-return"]
    cmds = [f"source {{{board_cfg}}}"]
    if args.serial:
        cmds.append(f"adapter serial {args.serial}")
    region = f"{heap:#x} {size:#x}"
    cmds += [
        "init", "halt", f"dump_image {{{tmp / names[0]}.bin}} {region}",
        "reset halt", f"dump_image {{{tmp / names[1]}.bin}} {region}",
        f"bp {init:#x} 2 hw", "resume", "wait_halt 20000",
        f"dump_image {{{tmp / names[2]}.bin}} {region}", f"rbp {init:#x}",
        f"bp {ret:#x} 2 hw", "resume", "wait_halt 20000",
        f"dump_image {{{tmp / names[3]}.bin}} {region}", f"rbp {ret:#x}",
        "resume", "shutdown",
    ]
    cfg = tmp / "openocd.cfg"
    cfg.write_text("\n".join(cmds) + "\n")
    scripts = openocd.parent.parent / "share" / "openocd" / "scripts"
    res = subprocess.run([openocd, "-s", scripts, "-f", cfg], capture_output=True, text=True,
                         check=False)
    (tmp / "openocd.log").write_text(res.stdout + res.stderr)
    for s in conns:
        s.close()
    dumps = []
    for n in names:
        f = tmp / f"{n}.bin"
        if res.returncode or not f.exists() or f.stat().st_size != size:
            fail(f"OpenOCD did not make {f.name}, see {tmp / 'openocd.log'}")
        dumps.append(f.read_bytes())

    def describe(d):
        nonzero = sum(1 for b in d if b)
        return nonzero, d.count(key_x) + d.count(key_x[::-1])

    for n, d in zip(names, dumps, strict=True):
        nonzero, copies = describe(d)
        print(f"{n}: {nonzero} non-zero bytes, {copies} copies of the public key")

    running, _, entry, after = dumps
    errors = []
    if describe(running)[1] == 0:
        errors.append("no copy of the public key in the heap while running, so the test "
                      "cannot tell whether key material is cleared")
    if entry == running:
        print("The heap is not zeroed before mbedtls_memory_buffer_alloc_init() "
              "and nothing used it before then")
    elif not any(entry):
        print("The heap was already zeroed on entry to mbedtls_memory_buffer_alloc_init()")
    else:
        errors.append("the heap changed between the reset and "
                      "mbedtls_memory_buffer_alloc_init(), so something used it first")
    if describe(after)[1]:
        errors.append("the public key is still in the heap after it was initialised")
    if any(after[HEADER_SIZE:]):
        errors.append("the heap is not zero after it was initialised")

    if args.keep or errors:
        print(f"dumps and OpenOCD log are in {tmp}")
    else:
        for f in tmp.iterdir():
            f.unlink()
        tmp.rmdir()
    if errors:
        fail("; ".join(errors))
    print("PASS: the heap is cleared when mbedTLS is initialised")


if __name__ == "__main__":
    main()
