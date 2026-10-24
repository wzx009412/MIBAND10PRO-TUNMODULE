#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线门：rc.d 自启动的「投 / 重投 / 移除 / 冲突」行为（真 Lua + 假 lvgl/io/os）。

只测一件事：我们往 /data 写的东西对不对、会不会撞别人的文件。

判据
  A1 按钮②投出 /data/rc.d/tun.sh，内容逐字节 == 期望（首行 `# top1`）
  A2 再按一次 → 内容不变（幂等）
  A3 全程不创建、不修改 /data/rc（管理器的产物）
  A4 全程不创建 /data/rc.d/.autorun.on（闸归管理器）
  A5 预先存在的 /data/rc.d/chaos.sh 一个字节不变
  A6 没有 /data/rc.d 时：按钮②失败，且 rc.d 下零写盘
  A7 按钮③移除：tun.sh 消失，/data/rc 与 chaos.sh 仍不变
  A8 移除后主功能文件（tun / capatch / ca.pem）一个都不少

跑法：
  C:/Users/Administrator/.workbuddy/binaries/python/envs/default/Scripts/python.exe tools/_sim_rc.py
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
MAIN = os.path.join(PACK, "_Lua", "main.lua")

TUN = "/data/tun/tun-3.101.043.bin"
CAP = "/data/ssl/capatch.elf"
PEM = "/data/ssl/ca.pem"
CA = "/data/certs/ca-certificates.crt"
RC = "/data/rc"
SH = "/data/rc.d/tun.sh"
OTHER = "/data/rc.d/chaos.sh"
GATE = "/data/rc.d/.autorun.on"

EXPECT = "\n".join([
    "# top",
    "set +e",
    "echo start > /data/tun/autostart.log",
    "insmod " + TUN + " tun",
    "echo tun >> /data/tun/autostart.log",
    "insmod " + CAP + " capatch",
    "echo cert >> /data/tun/autostart.log",
    "echo 1 > /dev/tunentry",
    "cat /dev/tunsvc > /data/tun/arm1.txt",
    "echo 2 > /dev/tunentry",
    "cat /dev/tunsvc > /data/tun/arm2.txt",
    "echo 3 > /dev/tunentry",
    "cat /dev/tunsvc > /data/tun/arm3.txt",
    "echo 4 > /dev/tunentry",
    "cat /dev/tunsvc > /data/tun/arm4.txt",
    "if [ -f /data/tundebug ];then",
    "echo 98 > /dev/tunentry",
    "fi",
    "echo armed >> /data/tun/autostart.log",
    "echo done >> /data/tun/autostart.log",
    "",
])

LUA_PRELUDE = r"""
local SRC = ...
fs = {}
buttons = {}
timers = {}
CMDS = {}
MD5MAP = {}

local function dir_of(p) return p:match("^(.*)/[^/]+$") or "/" end

-- ---- 极简 nsh ----
local function shell(cmd)
  cmd = cmd:match("^%s*(.-)%s*$")
  if cmd == "" then return "" end
  local a, b = cmd:match("^mkdir%s+%-p%s+(.+)$")
  if a then fs[a] = fs[a] or false; return "" end
  a = cmd:match("^rm%s+%-f%s+(.+)$")
  if a then
    for p in a:gmatch("%S+") do fs[p] = nil end
    return ""
  end
  if cmd:match("^insmod%s") then return "" end
  a = cmd:match("^md5%s+%-f%s+(%S+)%s*$")
  if a then local v = MD5MAP[a]; if v then return v .. "\n" end; return "MD5:" .. a end
  a = cmd:match("^ls%s+(%S+)%s*$")
  if a then
    if fs[a] == false then
      local out = {}
      for k in pairs(fs) do
        if k ~= a and dir_of(k) == a and fs[k] ~= false then out[#out+1] = k:match("[^/]+$") end
      end
      table.sort(out)
      return table.concat(out, "\n") .. (#out > 0 and "\n" or "")
    end
    if fs[a] ~= nil then return a:match("[^/]+$") .. "\n" end
    return "ls: " .. a .. ": No such file or directory\n"
  end
  a = cmd:match("^cat%s+(%S+)%s*$")
  if a then local d = fs[a]; if type(d) == "string" then return d end return "" end
  return ""
end

-- ---- io ----
io = {}
function io.open(path, mode)
  if mode == "rb" or mode == "r" then
    if fs[path] == nil then return nil end
    local pos, data = 0, fs[path] or ""
    local f = {}
    function f:read(n)
      if n == nil or n == "*a" then local s = data:sub(pos + 1); pos = #data; return s end
      local s = data:sub(pos + 1, pos + n); pos = pos + #s; return s
    end
    function f:seek(whence, off)
      if whence == "end" then return #data end
      if whence == "set" then pos = off or 0; return pos end
      return pos
    end
    function f:close() return true end
    return f
  end
  fs[path] = ""
  local f = {}
  function f:write(s) fs[path] = fs[path] .. s; return #s end
  function f:close() return true end
  return f
end

-- ---- os.execute（支持 > 与 >>）----
os = {}
function os.execute(line)
  local redir, append = nil, false
  local i = line:find(" >> ", 1, true)
  if i then redir, append = line:sub(i + 4), true; line = line:sub(1, i - 1) end
  if not redir then
    local j = line:find(" > ", 1, true)
    if j then redir = line:sub(j + 3); line = line:sub(1, j - 1) end
  end
  CMDS[#CMDS+1] = line
  local out = shell(line)
  if redir then
    if append and type(fs[redir]) == "string" then fs[redir] = fs[redir] .. out
    else fs[redir] = out end
  end
  return true
end

-- ---- lvgl ----
local Obj = {}
Obj.__index = Obj
function Obj:clear_flag() end
function Obj:add_flag() end
function Obj:onClicked(cb) self.cb = cb end
LAST_STATUS = nil
function Obj:set(t) if type(t) == 'table' and t.text then LAST_STATUS = t.text end end

lvgl = {}
lvgl.FLAG = { SCROLLABLE = 1, CLICKABLE = 2 }
lvgl.ALIGN = { CENTER = 1, TOP_LEFT = 2 }
lvgl.OPA = function(v) return v end
lvgl.HOR_RES = function() return 336 end
lvgl.VER_RES = function() return 480 end
lvgl.Font = function(n, s) return { name = n, size = s } end
function lvgl.Object(_, opt) return setmetatable({ opt = opt or {} }, Obj) end
function lvgl.Label(parent, opt)
  local o = setmetatable({ opt = opt or {} }, Obj)
  if parent and parent.opt and parent.opt.bg_color ~= nil and opt and opt.text then
    buttons[opt.text] = parent
    parent.label = opt.text
  end
  return o
end

local T = {}
T.__index = T
function T:ready() end
function T:resume() end
function T:delete() self.deleted = true end
function lvgl.Timer(opt)
  local o = setmetatable({ cb = opt.cb, deleted = false }, T)
  timers[#timers + 1] = o
  return o
end

SCRIPT_PATH = "/res/"   -- 表盘资源目录（本门不走按钮①，不需要真文件）
package.preload["lvgl"] = function() return lvgl end

-- ---- 加载被测脚本 ----
assert(load(SRC))()

-- ---- 对外：按按钮 ----
function press(label)
  local b = buttons[label]
  if not b then return "NO_BUTTON:" .. tostring(label) end
  if b.cb then b.cb() end
  for round = 1, 200 do
    local alive = false
    for _, t in ipairs(timers) do
      if not t.deleted then
        alive = true
        local ok = pcall(t.cb, t)
        if ok then break end
      end
    end
    if not alive then break end
  end
  timers = {}
  return "OK"
end
"""


def new_rt(fs, with_rcdir=True):
    import lupa
    lua = lupa.LuaRuntime(unpack_returned_tuples=True)
    src = open(MAIN, encoding="utf-8").read()
    lua.execute(LUA_PRELUDE, src)
    g = lua.globals()
    t = g.fs
    for k, v in fs.items():
        t[k] = v
    return lua


def read_fs(lua):
    t = lua.globals().fs
    out = {}
    for k in t.keys():
        out[str(k)] = t[k]
    return out


FAILS = []
OKS = []


def ok(cond, name, detail=""):
    if cond:
        OKS.append(name)
    else:
        FAILS.append(name + (("  [" + detail + "]") if detail else ""))
    print(("  ok   " if cond else "  FAIL ") + name + (("  " + detail) if (detail and not cond) else ""))


def md5(s):
    return hashlib.md5(s.encode("latin-1", "ignore")).hexdigest()


BASE = {
    TUN: "\x7fELFtun", CAP: "\x7fELFcap", PEM: "PEM", CA: "CA",
    "/data": False, "/data/tun": False, "/data/ssl": False, "/data/certs": False,
}


def case_install():
    fs = dict(BASE); fs["/data/rc.d"] = False; fs[OTHER] = "chaos\n"
    lua = new_rt(fs)
    g = lua.globals()
    r = g.press("2 写入开机自启")
    snap = read_fs(lua)
    got = snap.get(SH)
    ok(got == EXPECT, "A1 rc.d/tun.sh 内容逐字节正确", repr(got)[:120])
    ok(snap.get(RC) is None, "A3 没有写 /data/rc", repr(snap.get(RC))[:60])
    ok(snap.get(GATE) is None, "A4 没有创建 .autorun.on", repr(snap.get(GATE)))
    ok(snap.get(OTHER) == "chaos\n", "A5 chaos.sh 未被改动", repr(snap.get(OTHER))[:40])
    # 布防序列（A12）+ v74 坑（A13）
    lines12 = got.split("\n")
    seq = [l for l in lines12 if l.strip()]
    # 只认布防 1..4（97/98 是调试开关，不算布防）
    arm_idx = [i for i, l in enumerate(seq)
               if l.startswith("echo ") and l.endswith("> /dev/tunentry")
               and l.split()[1] in ("1", "2", "3", "4")]
    ok([seq[i].split()[1] for i in arm_idx] == ["1", "2", "3", "4"],
       "A12 自启脚本按 1→2→3→4 布防", str([seq[i] for i in arm_idx]))
    ok(all(i + 1 < len(seq) and seq[i + 1].startswith("cat /dev/tunsvc") for i in arm_idx),
       "A12b 每条布防后紧跟 cat /dev/tunsvc（触发执行）")
    ok(not any("> /dev/tunentry" in l and l.lstrip().startswith("cat ") for l in seq),
       "A13 没有用 cat 文件 > /dev/tunentry（v74 会拼不齐）")
    ok("if [ -f /data/tundebug ];then" in seq and "echo 98 > /dev/tunentry" in seq,
       "A14 只有 /data/tundebug 存在才开完整日志（echo 98）")
    _i = seq.index("if [ -f /data/tundebug ];then")
    ok(seq[_i + 1] == "echo 98 > /dev/tunentry" and seq[_i + 2] == "fi",
       "A14b 那个 if 只有一层、立刻 fi（不嵌套）", str(seq[_i:_i + 3]))

    # 幂等
    g.press("2 写入开机自启")
    snap2 = read_fs(lua)
    ok(snap2.get(SH) == EXPECT, "A2 再按一次内容不变（幂等）", repr(snap2.get(SH))[:80])
    return r


def case_no_rcdir():
    fs = dict(BASE)          # 没有 /data/rc.d
    lua = new_rt(fs)
    g = lua.globals()
    g.press("2 写入开机自启")
    snap = read_fs(lua)
    ok(snap.get(SH) is None, "A6 无 rc.d 时不投文件", repr(snap.get(SH)))
    ok(snap.get(RC) is None, "A6b 无 rc.d 时也不写 /data/rc", repr(snap.get(RC)))


def case_remove():
    fs = dict(BASE); fs["/data/rc.d"] = False; fs[OTHER] = "chaos\n"; fs[SH] = EXPECT
    fs[RC] = "set +e\nsh /data/rc.d/tun.sh\n"
    lua = new_rt(fs)
    g = lua.globals()
    before_rc = fs[RC]
    g.press("3 移除自启")
    snap = read_fs(lua)
    ok(snap.get(SH) is None, "A7 移除后 tun.sh 消失", repr(snap.get(SH)))
    ok(snap.get(RC) == before_rc, "A7b /data/rc 未被改动", repr(snap.get(RC))[:60])
    ok(snap.get(OTHER) == "chaos\n", "A7c chaos.sh 仍在", repr(snap.get(OTHER))[:40])
    missing = [p for p in (TUN, CAP, PEM) if snap.get(p) is None]
    ok(not missing, "A8 主功能文件一个不少", str(missing))


def case_res_len():
    # A9：长度不对 ⇒ 必须报 resource read failed
    fs = dict(BASE)
    fs["/res/shellpp_ii-3.101.043.bin"] = "X" * (75112 + 223684)      # 旧总长
    lua = new_rt(fs); g = lua.globals(); g.press("1 加载+布防（DNS 生效）")
    st = str(g.LAST_STATUS or "")
    ok("resource read failed" in st, "A9 长度不符时报 resource read failed", st[:90])
    # A10：长度正确 ⇒ 不得再报那句
    fs2 = dict(BASE)
    fs2["/res/shellpp_ii-3.101.043.bin"] = "X" * (75112 + 223684 + 8060 + 4038)
    lua2 = new_rt(fs2); g2 = lua2.globals(); g2.press("1 加载模块")
    st2 = str(g2.LAST_STATUS or "")
    ok("resource read failed" not in st2, "A10 长度正确时不再报该错", st2[:90])


def case_arm_merged():
    import re
    lua_src = open(MAIN, encoding="utf-8").read()
    def cst(name):
        m = re.search(name + r' = (?:[\d, ]*)"([0-9a-f]{32})"', lua_src)
        return m.group(1) if m else None
    md5map = {
        "/data/certs/ca-certificates.crt": cst("CA_MD5"),
        CAP: cst("CAP_MD5"),
        PEM: cst("PEM_MD5"),
    }
    build = re.search(r'local MODULE_BUILD = "([^"]+)"', lua_src).group(1)
    def csz(name):
        return int(re.search(name + r"[^=]*=\s*(\d+)", lua_src).group(1))
    total = csz("MODULE_SIZE") + csz("CA_SIZE") + csz("CAP_SIZE") + csz("PEM_SIZE")
    blob = build + "X" * (total - len(build))

    fs = dict(BASE)
    fs["/res/shellpp_ii-3.101.043.bin"] = blob
    # 同一个节点既是"状态页"又是"命令入口"：夹具一次给全（mt_build/mt_cmd_addr 必须在内，
    # 否则①的版本校验会先失败，跑不到布防）
    fs["/dev/tunentry"] = ("tun ipdns\nnetdev_ready=1\nmt_state=1\nmt_armed=0\n"
                           "mt_build=%s\nmt_cmd_addr=0x3c4a1090\n"
                           "mt_stage=1\nmt_reason=ok\nmt_preflight_rc=0\n"
                           "mt_mm_traps=1\nmt_hf_traps=1\nmt_mm_stub_seen=1\n"
                           "mt_vector_now=0x1\nmt_handler=0x1\n" % build) + "x" * 40

    lua = new_rt(fs)
    g = lua.globals()
    # 让 md5 -f 返回期望值（否则证书步骤会先失败，跑不到布防）
    mp = lua.globals().MD5MAP
    for k, v in md5map.items():
        if v:
            mp[k] = v
    g.press("1 加载+布防（DNS 生效）")
    cmds = [str(x) for x in lua.globals().CMDS.values()]
    mws = [c for c in cmds if c.strip().startswith("mw ")]
    got = [c.split("=")[-1].strip() for c in mws]
    ok(got[:3] == ["1", "2", "3"], "A11 按①即完成布防 mw=1/2/3", str(got[:6]))


if __name__ == "__main__":
    print("SIM-RC")
    case_install()
    case_no_rcdir()
    case_remove()
    case_res_len()
    case_arm_merged()
    print("SIM-RC: %s (%d)" % ("PASS" if not FAILS else "FAIL", len(OKS) + len(FAILS)))
    if FAILS:
        for f in FAILS:
            print("   - " + f)
    sys.exit(0 if not FAILS else 1)
