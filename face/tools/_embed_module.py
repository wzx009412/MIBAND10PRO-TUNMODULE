#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 tun_ipdns_fix 的模块 ELF 与 CA 证书合并成 [ELF][CA]，写入本工程两处槽位。

用法（工程根目录下）:
    python tools/_embed_module.py

校验:
  - 模块大小 == _Lua/main.lua 里的 MODULE_SIZE（取工程那一份为真源）
  - CA == 223684 B / md5 668c79b83142db3a8782313ffe8d8643（NAND 提取件）
  - 两处槽位（_Lua/ 与 resources/_lua/_Lua/）写入同一份字节

★★ v76 起：**自动同步** main.lua 里的 MODULE_SIZE / MODULE_BUILD。

为什么必须自动（这轮真机踩的坑）：
  main.lua 把这两个常量硬编码了，而它们必须跟模块产物一致：
    MODULE_SIZE  决定 raw:sub(1, MODULE_SIZE) 切模块段的长度
    MODULE_BUILD 用来确认「内存里跑的到底是不是这一版」
  之前它们只被**校验**、从不被写入 ⇒ 每次出新版都要人手改两个数字，
  忘了就发一个装不上去的包。

  而且本轮还踩了更重的一层：打包时我直接 `cp` 裸模块覆盖了
  _Lua/shellpp_ii-3.101.043.bin —— 那个文件不是裸模块，是 **[ELF][CA] 拼接产物**。
  裸模块一覆盖 ⇒ 设备端 resource 读出来 67688 B，而 main.lua 按 289112 校验
  ⇒ `FAIL: resource read failed: 67688（应 289112）`，包直接加载不上。
  ⇒ **这个文件只能由本工具写**，不能 cp。

  所以：本工具从模块二进制里读 MT_BUILD 串、拿实际长度，回写 main.lua，
  再拼接。这样「换模块」只需跑这一个脚本，不会再出现常量/拼接不同步。
"""
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # tunboot_mwz/
MOD_BIN = r'D:/GPTProject/tun_ipdns_fix/build/tun-3.101.043.bin'
CA_SRC = r'D:/GPTProject/tun_ipdns_fix/evidence/ca-certificates.10pro-nand.crt'
CA_MD5 = '668c79b83142db3a8782313ffe8d8643'
CA_SIZE = 223684
# 两处 main.lua 必须逐字节一致（pack_mwz 的 14 项自检会查，这里先自查）
MAIN_LUAS = ('_Lua/main.lua', 'resources/_lua/_Lua/main.lua')


def read_build_tag(mod):
    """从模块二进制里抠出 MT_BUILD 版本串（形如 v75-20261018-entrystream）。"""
    hits = re.findall(rb'v\d+-[0-9A-Za-z\-]+', mod)
    if not hits:
        raise SystemExit('FAIL: 模块二进制里找不到 MT_BUILD 版本串')
    # 取最长的那个 —— 版本串比 .rodata 里别的短串更像
    return max(hits, key=len).decode('ascii')


def sync_main_lua(mod, build):
    """把 MODULE_SIZE / MODULE_BUILD 回写进两处 main.lua。

    ★ 以 _Lua/main.lua 为真源：先把它改对，再**按字节**复制到 resources/ 那份。

    ★★ 踩过的坑：早先一版用「读文本 → 正则替换 → 写回」来同步两份，
       结果 Python 的 universal newlines 把 _Lua/main.lua 的 **CRLF** 悄悄
       归一成了 LF（31084 → 30428 B，差 656 = 656 行行尾），
       而 pack_mwz 的「两处逐字节一致」自检直接红。
       ⇒ 行尾属于源码的一部分，必须走二进制读写。
    """
    src = os.path.join(ROOT, '_Lua', 'main.lua')
    raw = open(src, 'rb').read()
    new = re.sub(rb'local MODULE_SIZE = \d+',
                 b'local MODULE_SIZE = %d' % len(mod), raw)
    new = re.sub(rb'local MODULE_BUILD = "[^"]*"',
                 b'local MODULE_BUILD = "%s"' % build.encode(), new)
    if new != raw:
        open(src, 'wb').write(new)
        print('  同步 _Lua/main.lua -> size=%d build=%s' % (len(mod), build))
    else:
        print('  _Lua/main.lua 已是最新（size=%d build=%s）' % (len(mod), build))

    for rel in MAIN_LUAS:
        dst = os.path.join(ROOT, rel)
        if open(dst, 'rb').read() != new:
            open(dst, 'wb').write(new)
            print('  同步 %s（按字节，行尾原样保留）' % rel)
    return new


def main():
    main_lua = os.path.join(ROOT, '_Lua', 'main.lua')
    mod = open(MOD_BIN, 'rb').read()
    build = read_build_tag(mod)

    # ★ 先同步常量（原来这里是「读出来然后拿它去校验」，等于让人肉保证一致性）
    sync_main_lua(mod, build)

    txt = open(main_lua, encoding='utf-8').read()
    msize = int(re.search(r'local MODULE_SIZE = (\d+)', txt).group(1))
    build2 = re.search(r'local MODULE_BUILD = "([^"]+)"', txt).group(1)

    if len(mod) != msize:
        print('FAIL: module size %d != MODULE_SIZE %d' % (len(mod), msize))
        return 1
    if build2.encode() not in mod:
        print('FAIL: MT_BUILD %s not found inside module binary' % build2)
        return 1

    ca = open(CA_SRC, 'rb').read()
    if len(ca) != CA_SIZE or hashlib.md5(ca).hexdigest() != CA_MD5:
        print('FAIL: CA blob mismatch (%d B, md5 %s)' % (len(ca), hashlib.md5(ca).hexdigest()))
        return 1

    data = mod + ca
    dsts = [os.path.join(ROOT, '_Lua', 'shellpp_ii-3.101.043.bin'),
            os.path.join(ROOT, 'resources', '_lua', '_Lua', 'shellpp_ii-3.101.043.bin')]
    for p in dsts:
        open(p, 'wb').write(data)
        print('wrote %s  (%d B)' % (p, len(data)))

    print('MODULE_BUILD =', build)
    print('module md5   =', hashlib.md5(mod).hexdigest())
    print('merged md5   =', hashlib.md5(data).hexdigest())
    print('EMBED-MODULE: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
