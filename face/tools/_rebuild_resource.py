#!/usr/bin/env python3
"""就地重建 resource.bin 里的 File payload（main.lua + 043 模块）。

背景：pack_mwz.py 的自检有两条
  "resource.bin 内嵌 main.lua == 工程 main.lua" / "内嵌 043 模块 == 工程那份"，
  改过 _Lua/main.lua 或模块之后必须重跑本脚本，否则那两条门 FAIL。
（原来的 Shellpp-ii-build/repack_resource.py 已不在，本脚本按 pack_mwz.py 里
 同一套解析口径反向重建。）

★ 关键：File payload 在文件里是**连续排布**的（addr 4000 起首尾相接），
  所以改任何一个的长度都必须把**其后所有记录的 addr 一起平移**，
  否则后面的 payload 全部错位（表现为解不出 UTF-8 文件名 / 门 FAIL）。
  —— 踩过：只改 length 不平移 addr，record 表看着正常、实际全错。

本脚本：重建整段 payload 区 + 重写记录表（addr/len），**不碰表头与其它区段**。
用法：python tools/_rebuild_resource.py [--project <dir>]
"""
import hashlib
import os
import struct
import sys

MAGIC = 0x1234A55A
BASE_HEADER_SIZE = 168
RECORD_SIZE = 16
FILE_TYPE = 5
NAME_OFF = 20


def u32(data, o):
    return struct.unpack_from("<I", data, o)[0]


def locate_records(data):
    """复刻 pack_mwz.parse_file_payloads 的遍历，返回全部 File 记录
    [(rec_off, addr, length, name)]，按物理地址排序。"""
    assert u32(data, 0) == MAGIC, "resource.bin 魔数不对"
    color_count, theme_count, recolor_count = data[24], data[28], data[29]
    header_size = BASE_HEADER_SIZE + (recolor_count or color_count) * 4
    protocol_minor = (u32(data, 16) >> 8) & 0xFF
    type_count = 12 if protocol_minor > 8 else 10
    table_size = 8 + type_count * 8

    pos = header_size
    locations = []
    for _ in range(theme_count):
        for kind in range(type_count):
            count = u32(data, pos + 8 + kind * 8)
            offset = u32(data, pos + 12 + kind * 8)
            if count:
                locations.append((offset, count))
        pos += table_size
        group_count = u32(data, pos + 68) >> 2
        pos += 72 + group_count * 4

    records = []
    for offset, count in locations:
        for i in range(count):
            rec = offset + i * RECORD_SIZE
            uid, _flags, addr, length = struct.unpack_from("<IIII", data, rec)
            if uid >> 24 != FILE_TYPE:
                continue
            packed = u32(data, addr)
            nlen = packed >> 24
            name = data[addr + NAME_OFF:addr + NAME_OFF + nlen].decode("utf-8")
            records.append((rec, addr, length, name))
    records.sort(key=lambda r: r[1])
    return records


def build_payload(name, body, reserved=b"\x00" * 16):
    """packed=(nlen<<24)|blen + 16B 保留 + name + body。
    reserved 保留原始 16 字节（实测恒为 0，但按原样搬运更稳）。"""
    nb = name.encode("utf-8")
    return struct.pack("<I", (len(nb) << 24) | len(body)) + reserved + nb + body


def patch(project):
    rb_path = os.path.join(project, "resource.bin")
    data = bytearray(open(rb_path, "rb").read())
    records = locate_records(data)
    if not records:
        raise SystemExit("resource.bin 里没有 File 记录")

    # 内嵌名 -> 新 body 的来源文件
    sources = {
        "_lua/_Lua/main.lua": os.path.join(project, "_Lua", "main.lua"),
        "_lua/_Lua/shellpp_ii-3.101.043.bin":
            os.path.join(project, "resources", "_lua", "_Lua",
                         "shellpp_ii-3.101.043.bin"),
    }

    block_start = min(r[1] for r in records)
    block_end = max(r[1] + r[2] for r in records)

    # ---- 1. 按原顺序拼出新的 payload 区 ----
    # payload 布局（★ 已用 v31 实测验证）：[4B packed=(nlen<<24)|blen][16B 保留]
    #                                [nlen B 名字 UTF-8][blen B body]
    # 记录表的 length == 20 + nlen + blen，且相邻 payload 首尾相接。
    blob = bytearray()
    placed = []            # [(rec_off, new_addr, new_len, name)]
    changed = []
    for rec, addr, length, name in records:
        src = sources.get(name)
        if src and os.path.exists(src):
            body = open(src, "rb").read()
            if data[addr:addr + length] != build_payload(name, body):
                changed.append(name)
                print("  替换 %-34s %d B -> %d B" % (name, length, len(body)))
        else:
            packed = u32(data, addr)
            nlen, blen = packed >> 24, packed & 0xFFFFFF
            reserved = bytes(data[addr + 4:addr + 20])
            body = bytes(data[addr + 20 + nlen:addr + 20 + nlen + blen])
        payload = build_payload(name, body) if src and os.path.exists(src) \
            else build_payload(name, body, reserved)
        payload = build_payload(name, body)
        new_addr = block_start + len(blob)
        placed.append((rec, new_addr, len(payload), name))
        blob += payload

    tail = bytes(data[block_end:])          # payload 区之后还有别的区段，原样保留
    out = bytes(data[:block_start]) + bytes(blob) + tail

    # ---- 2. 回写记录表的 addr/length ----
    outb = bytearray(out)
    for rec, new_addr, new_len, _name in placed:
        struct.pack_into("<I", outb, rec + 8, new_addr)
        struct.pack_into("<I", outb, rec + 12, new_len)

    open(rb_path, "wb").write(bytes(outb))
    print("  写出 %s (%d B, md5 %s)"
          % (rb_path, len(outb), hashlib.md5(bytes(outb)).hexdigest()))
    if changed:
        print("  替换 %d 条：%s" % (len(changed), ", ".join(changed)))
    else:
        print("  无需改动")
    print("REBUILD-RESOURCE: OK")
    return 0


def main():
    project = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    args = sys.argv[1:]
    if "--project" in args:
        project = args[args.index("--project") + 1]
    print("== 重建 resource.bin 内嵌 payload（project=%s）==" % project)
    return patch(project)


if __name__ == "__main__":
    sys.exit(main())
