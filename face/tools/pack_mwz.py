# -*- coding: utf-8 -*-
"""把 shellpp2-autorun 工程打成一个 .mwz 安装包（= 编辑器导出集的 ZIP）。

本工程 = **原版干净安装器**（reference/upstream-clean，544 行 main.lua）**原样**作基座，
只做两件事：
  1. 加一张「自启动」页（UI 版式抄我们改过的 shellpp-II-install-Lua-v2）；
  2. 让这张页按 REGISTER.md 的新规范落地 —— **只往 /data/rc.d/shellpp2.sh 投脚本**，
     和 chaos 在管理器下一样；**永不碰 /data/rc**，**不碰 flash**。

★ v2（2026-10-04 职责边界）：生成的 `shellpp2.sh` 是**纯命令** ——
  没有 `if`、没有 `sleep`、不碰 `autostart.on`；**闸与安全窗全部归管理器生成的 `/data/rc`**。
  （v1 那套"模块自带闸 + 5s/10s 延时"已废弃。）

→ 其余页面/文案/逻辑一字未改；上游那份 main.lua 是唯一真源，本工程的
  `_Lua/main.lua` = 它 + 新增页（944 行）。

.mwz 格式照原厂包反推（同 installer-work/_pack_v2.py）：
  * 条目用 deflate(method=8)；目录也写成条目, method=0, external_attr 带 MS-DOS 目录位
  * 顺序：顶层文件按名排序 -> 目录(先目录条目再内容) 按名排序
  * 不含 .git / .DS_Store / 任何构建期源目录（`_Lua/`、`tools/`、`out/`）

★ 打包侧只回答一个问题：**要装到设备上的字节，是不是离线门验过的那一份？**
  离线门（tools/_run_sim.py -> tools/_sim_autorun.lua）验的是**磁盘上的** `_Lua/main.lua`；
  设备真正读的是 **resource.bin 里嵌的那份**。所以这里必须把链子接起来：
      resource.bin 内嵌 main.lua  ==  resources/_lua/_Lua/main.lua  ==  _Lua/main.lua
  三条任一不等就是"改了源码忘了 repack"，直接停。
  改完 main.lua 的标准流程：
      python <Shellpp-ii-build>/repack_resource.py --project <本工程>
      python tools/pack_mwz.py

用法:
  python tools/pack_mwz.py                 # 打包 + 自检
  python tools/pack_mwz.py --out X.mwz
  python tools/pack_mwz.py --name 新名字    # 换 description.xml/manifest.xml 里的显示名后再打
"""
import argparse
import hashlib
import os
import re
import struct
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.abspath(os.path.join(HERE, ".."))
OUT_DEFAULT = os.path.join(PROJECT, "out", "shellpp2-autorun-v2.mwz")

SKIP_DIRS = {".git"}

# .mwz 里放的是编辑器导出集，不是整个仓库。
# 参照一个能用的原厂包：只含 capability.json / description.xml / editor.config.json /
# hashCode / preview/ / resource.bin / resources/ / uidmap.map。
# 本工程的 _Lua/ 是构建源（resources/_lua/_Lua/ 的镜像，manifest 只引用后者），不进包；
# tools/、out/、README.md、LICENSE 也不进包。
TOP_FILES = ["capability.json", "description.xml", "editor.config.json", "hashCode",
             "resource.bin", "uidmap.map"]
TOP_DIRS = ["preview", "resources"]

REQUIRED = [
    "capability.json", "description.xml", "editor.config.json", "hashCode",
    "resource.bin", "uidmap.map",
    "resources/manifest.xml", "resources/_lua/_Lua/main.lua",
    "resources/_lua/_Lua/shellpp_ii-3.101.043.bin",
]

DIR_ATTR = 0o20
FIXED_TIME = (1980, 1, 1, 0, 0, 0)   # 钉死时间戳 ⇒ 交付物可复现

FAILS = []
NCHK = [0]


def check(cond, label, extra=""):
    NCHK[0] += 1
    if cond:
        print("  ok   %s" % label)
    else:
        print("  FAIL %s  %s" % (label, extra))
        FAILS.append(label)
    return bool(cond)


def md5b(b):
    return hashlib.md5(b).hexdigest()


# ---------------------------------------------------------------- resource.bin

MAGIC = 0x1234A55A
BASE_HEADER_SIZE = 168
RECORD_SIZE = 16
FILE_TYPE = 5


def parse_file_payloads(data):
    """从 resource.bin 里取出所有 kind==5(File) 记录的**内嵌名 -> payload**。

    与 Shellpp-ii-build/repack_resource.py 的解析口径一致（那边是唯一真源，
    这里只读取不重写）。
    """
    def u32(o):
        return struct.unpack_from("<I", data, o)[0]

    assert u32(0) == MAGIC, "resource.bin 魔数不对"
    color_count, theme_count, recolor_count = data[24], data[28], data[29]
    header_size = BASE_HEADER_SIZE + (recolor_count or color_count) * 4
    protocol_minor = (u32(16) >> 8) & 0xFF
    type_count = 12 if protocol_minor > 8 else 10
    table_size = 8 + type_count * 8

    pos = header_size
    locations = []
    for _ in range(theme_count):
        for kind in range(type_count):
            count = u32(pos + 8 + kind * 8)
            offset = u32(pos + 12 + kind * 8)
            if count:
                locations.append((offset, count, kind))
        pos += table_size
        group_count = u32(pos + 68) >> 2
        pos += 72 + group_count * 4

    out = {}
    for offset, count, _kind in locations:
        for i in range(count):
            uid, _flags, addr, length = struct.unpack_from("<IIII", data, offset + i * RECORD_SIZE)
            if uid >> 24 != FILE_TYPE:
                continue
            payload = data[addr:addr + length]
            packed = struct.unpack_from("<I", payload, 0)[0]
            nlen, blen = packed >> 24, packed & 0xFFFFFF
            name = payload[20:20 + nlen].decode("utf-8")
            out[name] = payload[20 + nlen:20 + nlen + blen]
    return out


# ---------------------------------------------------------------- zip 组装

def collect(root):
    dirs, files, skipped = [], [], []
    for name in sorted(os.listdir(root)):
        if name in SKIP_DIRS or name.startswith("."):
            skipped.append(name)
            continue
        full = os.path.join(root, name)
        if os.path.isdir(full):
            if name not in TOP_DIRS:
                skipped.append(name)
                continue
            for base, subdirs, names in os.walk(full):
                subdirs[:] = sorted(d for d in subdirs if d not in SKIP_DIRS)
                rel = os.path.relpath(base, root).replace(os.sep, "/")
                dirs.append(rel)
                for nm in sorted(names):
                    if nm in (".DS_Store",) or nm.endswith(".mwz"):
                        continue
                    files.append(rel + "/" + nm)
        else:
            if name not in TOP_FILES:
                skipped.append(name)
                continue
            files.append(name)
    dirs.sort()
    files.sort()
    return dirs, files, skipped


def build(out_path):
    dirs, files, skipped = collect(PROJECT)
    missing = [p for p in REQUIRED if p not in files]
    assert not missing, "工程缺文件: %r" % missing

    top = [f for f in files if "/" not in f]
    rest = [f for f in files if "/" in f]
    ordered = [(f, False) for f in top]
    for d in dirs:
        ordered.append((d, True))
        for f in rest:
            if f.startswith(d + "/") and f.count("/") == d.count("/") + 1:
                ordered.append((f, False))

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, is_dir in ordered:
            info = zipfile.ZipInfo(name + "/" if is_dir else name, FIXED_TIME)
            if is_dir:
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = DIR_ATTR << 16
                z.writestr(info, b"")
            else:
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0
                with open(os.path.join(PROJECT, name.replace("/", os.sep)), "rb") as fh:
                    z.writestr(info, fh.read())
    return ordered, skipped


# ---------------------------------------------------------------- 自检

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT_DEFAULT)
    ap.add_argument("--name", default=None,
                    help="改 description.xml 的 <name> 与 resources/manifest.xml 的 name "
                         "后再打包（默认不动，仍叫 shellpp-ii-installer）")
    args = ap.parse_args()

    if args.name:
        for rel, pat in (("description.xml", r"(<name>)[^<]*(</name>)"),
                         ("resources/manifest.xml", r'(<Watchface[^>]*\bname=")[^"]*(")')):
            p = os.path.join(PROJECT, rel.replace("/", os.sep))
            txt = open(p, encoding="utf-8").read()
            new, n = re.subn(pat, lambda m: m.group(1) + args.name + m.group(2), txt, count=1)
            assert n == 1, "改名失败: " + rel
            open(p, "w", encoding="utf-8", newline="").write(new)
            print("  改名 %s -> %s" % (rel, args.name))
        # 名字进 manifest.xml ⇒ hashCode 要重算
        print("  ⚠ 改了 manifest.xml ⇒ 请重跑 repack_resource.py 以刷新 hashCode，"
              "否则下面 hashCode 自检会 FAIL")

    print("== 打包 ==")
    ordered, skipped = build(os.path.abspath(args.out))
    out = os.path.abspath(args.out)

    disk_main = open(os.path.join(PROJECT, "_Lua", "main.lua"), "rb").read()
    disk_bin = open(os.path.join(PROJECT, "_Lua", "shellpp_ii-3.101.043.bin"), "rb").read()

    print("== 自检 ==")
    with zipfile.ZipFile(out) as z:
        check(z.testzip() is None, "ZIP 无损坏")
        names = [i.filename for i in z.infolist()]
        check(names == [n + ("/" if d else "") for n, d in ordered], "条目顺序符合计划")

        # 1) manifest 的每个 File 引用都在包里且逐字节一致
        man = z.read("resources/manifest.xml").decode("utf-8")
        refs = re.findall(r'<File\s+fileName="([^"]+)"', man)
        check(len(refs) >= 5, "manifest 有 %d 个 File 引用" % len(refs))
        allok = True
        for ref in refs:
            arc = "resources/" + ref
            if arc not in names:
                allok = False
                break
            if z.read(arc) != open(os.path.join(PROJECT, "resources", ref.replace("/", os.sep)), "rb").read():
                allok = False
                break
        check(allok, "manifest 每个 File 引用在包内且与工程逐字节一致")

        # 2) 构建源 _Lua/ 与 真源 resources/_lua/_Lua/ 逐字节一致
        samelua = True
        for ref in refs:
            a = os.path.join(PROJECT, "resources", ref.replace("/", os.sep))
            b = os.path.join(PROJECT, "_Lua", os.path.basename(ref))
            if os.path.isfile(b) and open(a, "rb").read() != open(b, "rb").read():
                samelua = False
        check(samelua, "_Lua/ 构建源 与 resources/_lua/_Lua/ 逐字节一致")

        # 3) hashCode 三段自洽（capability.json, manifest.xml, resource.bin）
        hc = z.read("hashCode").decode("ascii")
        parts = hc.split(",")
        check(len(parts) == 3, "hashCode 是逗号连接的 3 段")
        for part, rel in zip(parts, ("capability.json", "resources/manifest.xml", "resource.bin")):
            check(part == hashlib.sha256(z.read(rel)).hexdigest(), "hashCode 段 == sha256(%s)" % rel)

        # 4) ★ 链子接起来：包内 main.lua == 磁盘 main.lua
        zmain = z.read("resources/_lua/_Lua/main.lua")
        check(zmain == disk_main, "包内 main.lua == 工程 _Lua/main.lua（md5 %s）" % md5b(disk_main)[:12])

        # 5) ★ resource.bin 内嵌的 payload == 磁盘文件（防"改了源码忘了 repack"）
        resblob = z.read("resource.bin")
        embedded = parse_file_payloads(resblob)
        check("_lua/_Lua/main.lua" in embedded, "resource.bin 里有 main.lua 记录")
        check(embedded.get("_lua/_Lua/main.lua") == disk_main,
              "★ resource.bin 内嵌 main.lua == 工程 main.lua（= 离线门验过的那份）",
              "md5 %s" % md5b(embedded.get("_lua/_Lua/main.lua", b""))[:12])
        check(embedded.get("_lua/_Lua/shellpp_ii-3.101.043.bin") == disk_bin,
              "★ resource.bin 内嵌 043 模块 == 工程那份（DQ 版 md5 %s）" % md5b(disk_bin)[:12])
        # ★★ v76：043 槽位不是裸模块，而是 [ELF][CA] 拼接体（main.lua 按
        #   MODULE_SIZE + CA_SIZE 校验总长）。v75 真机报
        #   `resource read failed: 67688（应 289112）` 就是把裸模块 cp 进了这个槽位。
        #   这里把「拼接结构」和「main.lua 常量」都钉死。
        _mtxt = open(os.path.join(PROJECT, "_Lua", "main.lua"), encoding="utf-8").read()
        _ms = re.search(r"local MODULE_SIZE = (\d+)", _mtxt)
        _cs = re.search(r"local CA_SIZE = (\d+)", _mtxt)
        check(disk_bin[:4] == b"\x7fELF", "★ 043 槽位以 ELF 魔数开头（模块段在前）")
        _capm = re.search(r"local CAP_SIZE, CAP_MD5 = (\d+), \"([0-9a-f]+)\"", _mtxt)
        _pemm = re.search(r"local PEM_SIZE, PEM_MD5 = (\d+), \"([0-9a-f]+)\"", _mtxt)
        if _ms and _cs and _capm and _pemm:
            _mo = int(_ms.group(1)); _ca = int(_cs.group(1))
            _csz, _cmd5 = int(_capm.group(1)), _capm.group(2)
            _psz, _pmd5 = int(_pemm.group(1)), _pemm.group(2)
            _co = _mo + _ca                 # 偏移由长度推导，和 main.lua 同一算法
            _po = _co + _csz
            _want = _mo + _ca + _csz + _psz
            check(len(disk_bin) == _want,
                  "★★ 043 槽位总长 == MODULE+CA+CAP+PEM（%d B）" % _want,
                  "实际 %d B" % len(disk_bin))
            check(len(disk_bin[_mo:_mo + _ca]) == _ca,
                  "★★ CA 段长度 == CA_SIZE（CA 段没丢）", "实际 %d" % len(disk_bin[_mo:_mo + _ca]))
            _capseg = disk_bin[_co:_co + _csz]
            check(len(_capseg) == _csz and md5b(_capseg) == _cmd5,
                  "★★ capatch 段 == 工程那份（%d B md5 %s）" % (_csz, _cmd5[:12]),
                  "%d B md5 %s" % (len(_capseg), md5b(_capseg)[:12]))
            _pemseg = disk_bin[_po:_po + _psz]
            check(len(_pemseg) == _psz and md5b(_pemseg) == _pmd5,
                  "★★ ca.pem 段 == 工程那份（%d B md5 %s）" % (_psz, _pmd5[:12]),
                  "%d B md5 %s" % (len(_pemseg), md5b(_pemseg)[:12]))

        # 6) 新规范：不投独立 rc 脚本文件；包里没有 rc
        rclike = [n for n in names if n.replace("resources/_lua/_Lua/", "").rstrip("/") == "rc"]
        check(not rclike, "包里没有独立的 rc 脚本文件（脚本由 main.lua 运行时生成）", str(rclike))

        reslen = len(resblob)
        binlen = len(z.read("resources/_lua/_Lua/shellpp_ii-3.101.043.bin"))

    print()
    print("mwz        : %s" % out)
    print("mwz 大小   : %d B" % os.path.getsize(out))
    print("sha256     : %s" % hashlib.sha256(open(out, "rb").read()).hexdigest())
    print("resource.bin: %d B   043 模块: %d B" % (reslen, binlen))
    print("main.lua   : %d B  md5 %s" % (len(disk_main), md5b(disk_main)))
    print("条目       : %d (含 %d 个目录)" % (len(ordered), sum(1 for _, d in ordered if d)))
    print("未打包     : %s" % (", ".join(skipped) if skipped else "(无)"))
    print()
    if FAILS:
        print("PACK-MWZ: FAIL (%d/%d)  %s" % (len(FAILS), NCHK[0], FAILS))
        return 1
    print("PACK-MWZ: PASS (%d)" % NCHK[0])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
