#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_pack_blob.py —— 从零件拼出 face/_Lua/shellpp_ii-3.101.043.bin（资源槽位）。

槽位是四段拼接体，长度必须与 `_Lua/main.lua` 顶部的常量一致：

    [0        .. MODULE_SIZE)              tun-3.101.043.bin
    [MODULE_SIZE .. +CA_SIZE)              CA bundle（旧方案遗留，当前不使用）
    [.. +CAP_SIZE)                         capatch.elf
    [.. +PEM_SIZE)                         ca.pem

用法（在仓库根目录）：

    # 1) 先编两个模块
    python modules/tun/build.py
    python modules/capatch/build_capatch.py

    # 2) 拼槽位（旧 CA 段默认从现有槽位里取；首次拼装或想换证书时用 --legacy-ca 指定）
    python face/tools/_pack_blob.py
    python face/tools/_pack_blob.py --legacy-ca path/to/ca-certificates.crt

    # 3) 重建 resource.bin + 打包
    cp face/_Lua/main.lua face/resources/_lua/_Lua/main.lua
    python face/tools/_rebuild_resource.py
    python face/tools/pack_mwz.py --out face/../dist/tunboot_cert.face

判据：每段的长度和 md5 都从 main.lua 读，不匹配就**一个字节都不写**。
"""
import argparse
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FACE = os.path.dirname(HERE)
REPO = os.path.dirname(FACE)
MAIN = os.path.join(FACE, "_Lua", "main.lua")
BLOB = os.path.join(FACE, "_Lua", "shellpp_ii-3.101.043.bin")

DEFAULT_TUN = os.path.join(REPO, "modules", "tun", "build", "tun-3.101.043.bin")
DEFAULT_CAP = os.path.join(REPO, "modules", "capatch", "capatch.elf")
DEFAULT_PEM = os.path.join(FACE, "assets", "ca.pem")


def consts():
    """从 main.lua 读四个长度和两个 md5（源码是唯一真源）。"""
    s = open(MAIN, encoding="utf-8").read()

    def num(name):
        m = re.search(name + r"[^\n=]*=\s*(\d+)", s)
        if not m:
            sys.exit("读不到 main.lua 里的 " + name)
        return int(m.group(1))

    def md5(name):
        m = re.search(name + r'[^\n]*"([0-9a-f]{32})"', s)
        return m.group(1) if m else None

    return dict(
        MODULE_SIZE=num("MODULE_SIZE"),
        CA_SIZE=num("CA_SIZE"),
        CAP_SIZE=num("CAP_SIZE"),
        PEM_SIZE=num("PEM_SIZE"),
        CAP_MD5=md5("CAP_MD5"),
        PEM_MD5=md5("PEM_MD5"),
    )


def md5(b):
    return hashlib.md5(b).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tun", default=DEFAULT_TUN, help="tun 模块（build.py 产物）")
    ap.add_argument("--capatch", default=DEFAULT_CAP, help="capatch 模块（build_capatch.py 产物）")
    ap.add_argument("--pem", default=DEFAULT_PEM, help="ca.pem（证书链）")
    ap.add_argument("--legacy-ca", default=None,
                    help="旧 CA bundle；不给就从现有槽位里抠出来（首次拼装必须给）")
    ap.add_argument("--out", default=BLOB)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    c = consts()
    print("main.lua 常量: MODULE=%d CA=%d CAP=%d PEM=%d" %
          (c["MODULE_SIZE"], c["CA_SIZE"], c["CAP_SIZE"], c["PEM_SIZE"]))

    tun = open(a.tun, "rb").read()
    cap = open(a.capatch, "rb").read()
    pem = open(a.pem, "rb").read()

    if len(tun) != c["MODULE_SIZE"]:
        sys.exit("tun 长度不符: %d ≠ MODULE_SIZE %d（先重编模块，或改 main.lua）"
                 % (len(tun), c["MODULE_SIZE"]))
    if len(cap) != c["CAP_SIZE"]:
        sys.exit("capatch 长度不符: %d ≠ CAP_SIZE %d" % (len(cap), c["CAP_SIZE"]))
    if len(pem) != c["PEM_SIZE"]:
        sys.exit("ca.pem 长度不符: %d ≠ PEM_SIZE %d" % (len(pem), c["PEM_SIZE"]))
    if c["CAP_MD5"] and md5(cap) != c["CAP_MD5"]:
        sys.exit("capatch md5 不符: %s ≠ %s" % (md5(cap), c["CAP_MD5"]))
    if c["PEM_MD5"] and md5(pem) != c["PEM_MD5"]:
        sys.exit("ca.pem md5 不符: %s ≠ %s" % (md5(pem), c["PEM_MD5"]))

    if a.legacy_ca:
        ca = open(a.legacy_ca, "rb").read()
    else:
        if not os.path.exists(a.out):
            sys.exit("没有现成槽位可抠旧 CA 段，请用 --legacy-ca 指定")
        old = open(a.out, "rb").read()
        ca = old[c["MODULE_SIZE"]:c["MODULE_SIZE"] + c["CA_SIZE"]]
    if len(ca) != c["CA_SIZE"]:
        sys.exit("旧 CA 段长度不符: %d ≠ CA_SIZE %d" % (len(ca), c["CA_SIZE"]))

    blob = tun + ca + cap + pem
    total = sum((c["MODULE_SIZE"], c["CA_SIZE"], c["CAP_SIZE"], c["PEM_SIZE"]))
    if len(blob) != total:
        sys.exit("总长不符: %d ≠ %d" % (len(blob), total))

    print("  tun      %6d  %s" % (len(tun), md5(tun)[:16]))
    print("  CA(legacy) %4d  %s" % (len(ca), md5(ca)[:16]))
    print("  capatch  %6d  %s" % (len(cap), md5(cap)[:16]))
    print("  ca.pem   %6d  %s" % (len(pem), md5(pem)[:16]))
    print("  合计     %6d" % len(blob))

    if a.dry_run:
        print("dry-run：未写盘")
        return 0

    old = open(a.out, "rb").read() if os.path.exists(a.out) else b""
    if old == blob:
        print("槽位已是目标内容，未改动")
        return 0
    open(a.out, "wb").write(blob)
    print("已写 " + a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
