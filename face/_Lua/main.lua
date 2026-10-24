-- TUN module loader + boot autostart writer, built on the shellpp2-autorun project.
--
-- 与 shellpp 安装器同源：同一套 lvgl 写法、同一套字体（MiSans-Demibold/Regular）、
-- 同为 _Lua/ 同级资源。
--
-- 本工程的 _Lua/shellpp_ii-3.101.043.bin 这个槽位里放的是 **tun 模块**
-- （42,072 B / md5 2af14958…），本 Lua 从 SCRIPT_PATH 读它并 insmod。
-- 该版本**加载时零风险**：只做只读探测 + 上报，不装向量、不动 MPU。
-- 陷阱改为**分级布防**，两条路都行：
--   ① 按钮③「分级布防」：自动读 tunstat 取 mt_cmd_addr → 依次 mw 1/2/3，
--      每一步的完整报告落盘到 /data/mt-A.txt / mt-B.txt / mt-C.txt（外加 mt-0/mt-final），
--      所以即使某一步把系统搞挂，**上一步的报告也已经在盘上**，重启后直接 cat 出来。
--   ② 手动：nsh 里 `mw <tunstat 里的 mt_cmd_addr>=<n>`，再读一次任一节点即执行：
--      1 = 装双向量+使能 MEMFAULTENA（安全）   2 = 开 MPU + 闪存预检 + 合成陷阱往返自检
--      3 = 真正布防解析器窗口 + 替换路径验证   4 = 全量回滚   7 = 一把跑完整梯子
-- 任一关不过都会全量回滚并在 mt_reason 里写明原因；任何"handler 内再异常"都会被
-- 回滚+跳过出错指令（防死循环），所以最坏情况是"陷阱没装成"，不是卡死。
--
-- 三个自检标记，装完用 nsh 一读就知道跑到哪一步：
--   /data/tunboot-1.txt  脚本开始执行
--   /data/tunboot-2.txt  点了按钮①，模块资源读成功
--   /data/tunboot-3.txt  界面控件全部建完
local lvgl = require("lvgl")

local function early_write(path, text)
    local ok, file = pcall(io.open, path, "wb")
    if not ok or not file then return end
    pcall(file.write, file, text)
    pcall(file.close, file)
end

early_write("/data/tunboot-1.txt", "script started\n")

local W, H = lvgl.HOR_RES(), lvgl.VER_RES()
local MODULE_RES = SCRIPT_PATH .. "shellpp_ii-3.101.043.bin"
local MODULE_SIZE = 74640
-- 模块里编进去的构建标识（MT_BUILD）。① 会用它确认"内存里跑的到底是不是这一版"：
-- 模块基址每次都变，所以不能拿地址当版本号，只能靠这个串。
local MODULE_BUILD = "v108-20261024-dbg-flag"
local MODULE_DIR = "/data/tun"
local MODULE_DST = MODULE_DIR .. "/tun-3.101.043.bin"
local MODULE_NEW = MODULE_DST .. ".new"
local MODULE_BAK = MODULE_DST .. ".bak"
local INSMOD_LOG = "/data/tunboot-insmod.log"
local RCDIR = "/data/rc.d"
local RCPATH = "/data/rc"
local GATE = RCDIR .. "/.autorun.on"
local ASLOG = RCDIR .. "/.autorun.log"
local LOGPATH = "/data/tunboot.log"
local TMP = "/data/tunboot.tmp"
-- ★ v43：CA 证书（修 HTTPS 的 curl code 60）。10Pro 固件把 /etc/ssl/curl/ca-certificates.crt
-- （curl 编译默认 CA 路径，mbedtls 后端）裁掉了，根文件系统又是只读 romfs（写不进、也挂不上）
-- ⇒ 改走 libcurl 官方支持的 **CURL_CA_BUNDLE 环境变量** 指向 /data 里的证书副本（nsh `set` 可设；
-- 环境变量在 RAM ⇒ 每次启动都要重设，所以挂在①流程里自动做）。
-- 证书本体 = curl 官方 Mozilla bundle（223,684 B，就是本机出厂镜像里那份），32KB × 7 片打进资源。
local CA_DIR = "/data/certs"
local CA_DST = CA_DIR .. "/ca-certificates.crt"
local CA_PARTS = 7
local CA_SIZE = 223684
local CA_MD5 = "668c79b83142db3a8782313ffe8d8643"

-- ★ v44：证书改走「模块直塞全局 CA 链」（旧 CURL_CA_BUNDLE 方案实测无效，保留旧段不再使用）
--   资源尾部追加两段：[capatch.elf 8124][ca.pem 4038]
local CAP_SIZE, CAP_MD5 = 8060, "f7b4386cd2381a9da22222b8962969fb"
local CAP_OFF = MODULE_SIZE + CA_SIZE
local PEM_SIZE, PEM_MD5 = 4038, "f51206b71f8bd8344e593f60137c708d"
local PEM_OFF = CAP_OFF + CAP_SIZE
local CAP_DIR = "/data/ssl"
local CAP_DST = CAP_DIR .. "/capatch.elf"
local PEM_DST = CAP_DIR .. "/ca.pem"

local lines = {}
local busy = false
local queue = nil
local runner = nil
local module_body = nil
local ca_blob = nil   -- ★ v43：模块资源尾部的 CA 证书段（223,684 B）
local cap_blob, pem_blob = nil, nil   -- ★ v44：capatch 模块 + 4KB 证书包

local function read_all(path, mode)
    if type(io) ~= "table" or type(io.open) ~= "function" then return nil end
    local file = io.open(path, mode or "rb")
    if not file then return nil end
    local ok, content = pcall(file.read, file, "*a")
    pcall(file.close, file)
    if not ok or type(content) ~= "string" then return nil end
    return content
end

local function write_all(path, content)
    if type(io) ~= "table" or type(io.open) ~= "function" then return false, "io unavailable" end
    local file = io.open(path, "wb")
    if not file then return false, "open failed" end
    local wok, wres = pcall(file.write, file, content)
    local cok, cres = pcall(file.close, file)
    if not (wok and wres ~= nil and cok and cres ~= nil) then return false, "write failed" end
    if read_all(path) ~= content then return false, "readback mismatch" end
    return true
end

local function sh(cmd)
    if type(os) ~= "table" or type(os.execute) ~= "function" then return false end
    local called, a = pcall(os.execute, cmd)
    if not called then return false end
    if type(a) == "number" then return a == 0 end
    return a == true
end

local function sh_out(cmd)
    sh(cmd .. " > " .. TMP)
    local out = read_all(TMP) or ""
    sh("rm -f " .. TMP)
    return out
end

local function one_line(text)
    return (tostring(text):gsub("[%r%n]+", " ")):sub(1, 120)
end

local status = nil
local load_button = nil
local rc_button = nil
local arm_button = nil
local rm_button = nil
local ok_note = nil

local function set_status(text, color)
    if status then pcall(status.set, status, { text = text, text_color = color or 0xB3B3B3 }) end
end

local function log_append(text)
    lines[#lines + 1] = text
    write_all(LOGPATH, table.concat(lines, "\n") .. "\n")
end

-- 开机自启：与 10pro.autorun 管理器同形，保留防砖闸
-- 心跳(闸外) -> 门 -> 扣闸 -> insmod(不延时) -> 两个安全窗 -> cleared -> 放行
local function rc_body()
    -- 契约（REGISTER.md v0.6.6）：模块只写「自己的命令」；闸与安全窗口归管理器。
    -- 首行 top1 是标记（nsh 当注释）。
    --
    -- ★ 布防也放进来了：模块 v74 起 /dev/tunentry 支持流式命令
    --   `echo <n> > /dev/tunentry`，**不需要 mt_cmd_addr**（那个地址每次开机都变）。
    --   注意：必须用 echo，**不能用 `cat 文件 > /dev/tunentry`** ——
    --   后者在 nsh 里是 4 字节步长散开的（entry_head = 6d 00 00 00 74 …），永远拼不齐。
    --   每条 echo 之后 cat /dev/tunsvc：读诊断页会同步执行 mt_cmd_poll，
    --   把上一条命令在同一任务上下文里跑掉，并把当时的状态落盘留证。
    return table.concat({
        "# top",
        "set +e",
        "echo start > /data/tun/autostart.log",
        "insmod " .. MODULE_DST .. " tun",
        "echo tun >> /data/tun/autostart.log",
        "insmod " .. CAP_DST .. " capatch",
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
    }, "\n")
end

local function finish(ok, message)
    if runner then pcall(runner.delete, runner); runner = nil end
    busy = false
    if load_button then pcall(load_button.add_flag, load_button, lvgl.FLAG.CLICKABLE) end
    if rc_button then pcall(rc_button.add_flag, rc_button, lvgl.FLAG.CLICKABLE) end
    if arm_button then pcall(arm_button.add_flag, arm_button, lvgl.FLAG.CLICKABLE) end
    if rm_button then pcall(rm_button.add_flag, rm_button, lvgl.FLAG.CLICKABLE) end
    if ok then
        set_status(ok_note or message, 0x8FF0A4)
    else
        set_status(tostring(message) .. "\nsee " .. LOGPATH, 0xFF9A9A)
        log_append("FAIL: " .. tostring(message))
    end
end

local function step(timer)
    if type(queue) ~= "table" or #queue == 0 then
        log_append("done")
        finish(true, "完成\n日志 " .. LOGPATH)
        return
    end
    local fn = table.remove(queue, 1)
    local called, good, why = pcall(fn)
    if not called then finish(false, tostring(good)); return end
    if not good then finish(false, tostring(why)); return end
    timer:ready()
end

local function start_action(steps)
    if busy then return end
    busy = true
    lines = {}
    ok_note = nil
    if load_button then pcall(load_button.clear_flag, load_button, lvgl.FLAG.CLICKABLE) end
    if rc_button then pcall(rc_button.clear_flag, rc_button, lvgl.FLAG.CLICKABLE) end
    if arm_button then pcall(arm_button.clear_flag, arm_button, lvgl.FLAG.CLICKABLE) end
    if rm_button then pcall(rm_button.clear_flag, rm_button, lvgl.FLAG.CLICKABLE) end
    queue = steps
    runner = lvgl.Timer { period = 100, repeat_count = -1, paused = true, cb = function(t)
        local called, why = pcall(step, t)
        if not called then finish(false, tostring(why)) end
    end }
    if not runner then finish(false, "timer creation failed"); return end
    runner:resume()
    runner:ready()
end

local load_steps = {
    function()
        -- ★ v43：这个资源文件 = [模块 ELF (MODULE_SIZE B)][CA 证书 (CA_SIZE B)] 两段拼接。
        --   (不能新增 resource 记录——resource.bin 表区插不进；模块文件尾部是"免费"的载体)
        local raw = read_all(MODULE_RES)
        local RES_TOTAL = MODULE_SIZE + CA_SIZE + CAP_SIZE + PEM_SIZE
        if type(raw) ~= "string" or #raw ~= RES_TOTAL then
            return false, "resource read failed: " .. tostring(raw and #raw or "nil") ..
                          "（应 " .. tostring(RES_TOTAL) .. "）"
        end
        module_body = raw:sub(1, MODULE_SIZE)
        ca_blob = raw:sub(MODULE_SIZE + 1, MODULE_SIZE + CA_SIZE)
        cap_blob = raw:sub(CAP_OFF + 1, CAP_OFF + CAP_SIZE)
        pem_blob = raw:sub(PEM_OFF + 1, PEM_OFF + PEM_SIZE)
        local has = module_body:find(MODULE_BUILD, 1, true) ~= nil
        early_write("/data/tunboot-2.txt", "module read " .. tostring(#raw) .. "\n")
        log_append("module+CA " .. tostring(#raw) .. " B build=" .. MODULE_BUILD ..
                   (has and " ok" or " MISSING"))
        set_status("加载模块…", 0xFFD60A)
        return true
    end,
    function()
        sh("mkdir -p " .. MODULE_DIR)
        local old = read_all(MODULE_DST)
        if old then
            local ok = write_all(MODULE_BAK, old)
            log_append(ok and "backup ok" or "backup failed")
        else
            log_append("no old module")
        end
        return true
    end,
    function()
        local ok, why = write_all(MODULE_NEW, module_body)
        if not ok then return false, "stage write failed: " .. tostring(why) end
        log_append("stage write + readback ok")
        return true
    end,
    function()
        local old = read_all(MODULE_DST)
        local ok, why = write_all(MODULE_DST, module_body)
        if not ok then
            if old then write_all(MODULE_DST, old) end
            return false, "target write failed: " .. tostring(why)
        end
        sh("rm -f " .. MODULE_NEW)
        log_append("written " .. MODULE_DST)
        return true
    end,
    function()
        local ok = sh("insmod " .. MODULE_DST .. " tun > " .. INSMOD_LOG)
        local out = one_line(read_all(INSMOD_LOG) or "")
        log_append("insmod " .. (ok and "ok" or "fail") .. " out: " .. (out ~= "" and out or "(empty)"))
        log_append("/dev/tun: " .. (one_line(sh_out("ls -l /dev/tun")) ~= "" and "present" or "missing"))
        return true
    end,
    function()
        -- 内存里那一份到底是哪一版？模块无法卸载，所以换了模块必须先重启。
        local st = sh_out("cat /dev/tunentry")
        local run = st and st:match("mt_build=([^%s]+)") or nil
        if run == MODULE_BUILD then
            log_append("running module build=" .. run .. " (matches this file)")
            return true
        end
        -- 内存里不是这一版：把动作写死，别让它被当成"完成"
        log_append("running module build=" .. tostring(run) .. " <> file " .. MODULE_BUILD)
        return false, "模块文件已写好，但内存里跑的还不是这一版（读到 " ..
                      tostring(run) .. "，应为 " .. MODULE_BUILD ..
                      "）。请重启手表，再按一次①，然后才按③"
    end,
    -- ★ v43 CA 步骤 1/2：证书文件（持久在 /data；已有就跳过；首次从 ca_blob 切片拼装 + MD5 校验）
    -- ★ v46 修正两处：① 设备的 md5 不带 -f 算的是「参数字符串本身」的哈希，校验文件必须 `md5 -f <path>`
    --                （help "[-f] <string or filepath>"，反汇编确认：不带 -f 走 strlen(argv[1]) 那条路）；
    --                ② "已存在"不能盲信：md5 -f 真校验，不符就删掉重装（自愈；也让 ls 判据的抖动无副作用）。
    function()
        if type(ca_blob) ~= "string" or #ca_blob ~= CA_SIZE then
            return false, "CA 段长度不对: " .. tostring(ca_blob and #ca_blob or "nil")
        end
        sh("mkdir -p " .. CA_DIR)
        local out = sh_out("ls -l " .. CA_DST)
        if type(out) == "string" and #out > 16 then
            local mo = sh_out("md5 -f " .. CA_DST)
            if type(mo) == "string" and string.lower(mo):find(CA_MD5, 1, true) then
                log_append("CA file present, md5 ok -> skip")
                set_status("证书已就绪 ✓", 0x8FF0A4)
                return true
            end
            log_append("CA file present but md5 bad: " .. one_line(mo) .. " -> rebuild")
            sh("rm -f " .. CA_DST)
        end
        local i, total = 0, 0
        for i = 0, CA_PARTS - 1 do
            local from = i * 32768 + 1
            local part = ca_blob:sub(from, from + 32767)
            if type(part) ~= "string" or #part == 0 then
                return false, "CA 分片 " .. i .. " 切片失败"
            end
            local ok, why = write_all(CA_DIR .. "/ca.c" .. i, part)
            if not ok then return false, "写证书分片 " .. i .. " 失败: " .. tostring(why) end
            total = total + #part
        end
        local cat = "cat " .. CA_DIR .. "/ca.c0"
        for i = 1, CA_PARTS - 1 do cat = cat .. " " .. CA_DIR .. "/ca.c" .. i end
        sh(cat .. " > " .. CA_DST)
        sh("rm -f " .. CA_DIR .. "/ca.c0 " .. CA_DIR .. "/ca.c1 " .. CA_DIR .. "/ca.c2 " ..
           CA_DIR .. "/ca.c3 " .. CA_DIR .. "/ca.c4 " .. CA_DIR .. "/ca.c5 " .. CA_DIR .. "/ca.c6")
        local md5o = sh_out("md5 -f " .. CA_DST)
        log_append("CA install " .. tostring(total) .. "B md5=" .. one_line(md5o))
        if type(md5o) ~= "string" or not string.lower(md5o):find(CA_MD5, 1, true) then
            return false, "证书拼装校验失败（md5 -f 不符, 文件 " ..
                          tostring(#(read_all(CA_DST) or "")) .. "B）: " .. one_line(md5o)
        end
        set_status("证书已装好 ✓", 0x8FF0A4)
        return true
    end,
    -- ★ v43 CA 步骤 2/2：CURL_CA_BUNDLE 环境变量
    -- ★ v47（真机实测后降级）：nsh 的 `set` 改的是**那条命令自己的短命子进程**的环境
    --   （NuttX 环境变量按任务私有；os.execute 每条命令都是新进程）⇒ 这里设的变量
    --   活不过本条命令，之后的 `env` 永远看不到；对快应用 fetch / 手工 curl 同样无效
    --   （环境变量不跨进程）。证书线按用户指示暂停 ⇒ 本步骤降级为"尽力而为 + 如实留痕"，
    --   不再让 ① 整体失败；恢复证书线时把 return 改回 false 即可（日志里有原样记录）。
    function()
        sh("set CURL_CA_BUNDLE " .. CA_DST)
        local out = sh_out("env")
        local hit = type(out) == "string" and out:find("CURL_CA_BUNDLE=" .. CA_DST, 1, true) ~= nil
        log_append("CURL_CA_BUNDLE " ..
                   (hit and "ok" or "not visible to this shell（跨进程无效；证书线暂停中，按非致命处理）"))
        if hit then
            set_status("证书 + CURL_CA_BUNDLE 就绪 ✓", 0x8FF0A4)
        else
            set_status("证书已就位 ✓（env 跨进程无效，证书线暂停）", 0xFFD60A)
        end
        return true
    end,
    -- ★ v44：装证书模块（安全版 capatch）+ 证书包，并 insmod 一次
    function()
        if type(cap_blob) ~= "string" or #cap_blob ~= CAP_SIZE then
            return false, "capatch 段长度不对: " .. tostring(cap_blob and #cap_blob or "nil")
        end
        if type(pem_blob) ~= "string" or #pem_blob ~= PEM_SIZE then
            return false, "ca.pem 段长度不对: " .. tostring(pem_blob and #pem_blob or "nil")
        end
        sh("mkdir -p " .. CAP_DIR)
        if not write_all(CAP_DST, cap_blob) then return false, "写 capatch.elf 失败" end
        if not write_all(PEM_DST, pem_blob) then return false, "写 ca.pem 失败" end
        local mo = one_line(sh_out("md5 -f " .. CAP_DST))
        local po = one_line(sh_out("md5 -f " .. PEM_DST))
        log_append("capatch md5=" .. mo)
        log_append("ca.pem  md5=" .. po)
        if not string.lower(mo):find(CAP_MD5, 1, true) then return false, "capatch md5 不符" end
        if not string.lower(po):find(PEM_MD5, 1, true) then return false, "ca.pem md5 不符" end
        sh("insmod " .. CAP_DST .. " capatch > /data/tunboot-cap.log")
        local pr = one_line(sh_out("cat /dev/capatch"))
        log_append("capatch: " .. pr)
        return true
    end,

}

local rc_steps = {
    function()
        -- 管理器没装 ⇒ 报错退出，一个字节都不写（不许自己 mkdir rc.d）
        local ls = sh_out("ls " .. RCDIR)
        if type(ls) ~= "string" or ls:find("No such", 1, true) or #ls < 3 then
            return false, "没有 " .. RCDIR .. " ⇒ 管理器没装（先装 10pro.autorun 表盘）"
        end
        local body = rc_body()
        local ok, why = write_all(RCDIR .. "/tun.sh", body)
        if not ok then return false, "写 rc.d/tun.sh 失败: " .. tostring(why) end
        log_append("rc.d/tun.sh " .. #body .. " B 已投（首行 # top1）")
        return true
    end,
    function()
        local back = read_all(RCDIR .. "/tun.sh") or ""
        log_append("回读 rc.d/tun.sh " .. #back .. " B")
        if back ~= rc_body() then return false, "rc.d/tun.sh 回读不符" end
        log_append("下一步：10pro.autorun → [3 模块管理] → [2 重建自启动]")
        set_status("已投 rc.d/tun.sh\n去管理器按 [2 重建自启动]", 0x8FF0A4)
        return true
    end,
}

-- ============ 移除自启动（按钮⑥）============
-- 契约：只删自己那一片 /data/rc.d/tun.sh；**不碰 /data/rc、不碰闸**。
-- /data/rc 里那行要等管理器按 [2 重建自启动] 才会消失。
-- 反向判据：主功能文件（模块/证书）一个都不许少。
local rm_steps = {
    function()
        local path = RCDIR .. "/tun.sh"
        local before = read_all(path)
        if type(before) ~= "string" then
            log_append("rc.d/tun.sh 不存在，无需移除")
            set_status("本来就没有 tun.sh", 0x8FF0A4)
            return true
        end
        sh("rm -f " .. path)
        if read_all(path) ~= nil then return false, "rm 之后仍能读到 tun.sh" end
        log_append("已移除 " .. path .. "（" .. #before .. " B）")
        local keep = { MODULE_DST, CAP_DST, PEM_DST, CA_DST }
        local i
        for i = 1, #keep do
            if read_all(keep[i]) == nil then
                return false, "误删了主功能文件: " .. keep[i]
            end
        end
        log_append("主功能文件完好（模块/证书未动）")
        return true
    end,
    function()
        log_append("next: 10pro.autorun → [2 重建自启动]")
        set_status("已移除 /data/rc.d/tun.sh\n去管理器按 [2 重建自启动] 才会从 /data/rc 消失", 0xFFD60A)
        return true
    end,
}

-- ============ 分级布防（按钮③）============
-- 读 /dev/tunentry 取 mt_cmd_addr，然后依次下发 1/2/3，并把每一步的完整
-- /dev/tunentry 报告落盘。命令是"读节点时才执行"，所以每条 mw 后面都必须
-- 跟一次节点读取；这里用 sh_out（重定向到临时文件再读回）实现。
local ARM = { addr = nil, files = {}, stop = nil }

local function field_of(text, key)
    if type(text) ~= "string" then return nil end
    local v = text:match(key .. "=([^\r\n]+)")
    if v then v = v:gsub("%s+$", "") end
    return v
end

local function arm_stage(cmd, tag)
    return function()
        if ARM.stop then
            return false, ARM.stop .. "；已停止。报告： " .. table.concat(ARM.files, " ")
        end
        if not ARM.addr then return false, "未取到 mt_cmd_addr（模块没加载？）" end
        sh("mw " .. ARM.addr .. "=" .. cmd)
        local out = sh_out("cat /dev/tunentry")
        if type(out) ~= "string" or #out < 32 then
            return false, tag .. "：读 /dev/tunentry 失败"
        end
        local path = "/data/mt-" .. tag .. ".txt"
        local ok = write_all(path, out)
        ARM.files[#ARM.files + 1] = path .. (ok and "" or "(写失败)")
        local stage = field_of(out, "mt_stage") or "?"
        local reason = field_of(out, "mt_reason") or "?"
        local pf = field_of(out, "mt_preflight_rc") or "?"
        local mm = field_of(out, "mt_mm_traps") or "?"
        local hf = field_of(out, "mt_hf_traps") or "?"
        local seen = field_of(out, "mt_mm_stub_seen") or "?"
        local skips = field_of(out, "mt_skips") or "?"
        log_append(tag .. " stage=" .. stage .. " reason=" .. reason ..
                   " preflight=" .. pf .. " mm=" .. mm .. " hf=" .. hf ..
                   " stub=" .. seen .. " skips=" .. skips)
        local line = "关" .. tag .. " stage=" .. stage .. " reason=" .. reason
        set_status("布防 " .. tag .. " 完成\n" .. line, 0x8FF0A4)
        if tag == "A" then
            local now = field_of(out, "mt_vector_now")
            local h = field_of(out, "mt_handler")
            local shcsr = field_of(out, "mt_shcsr_after")
            log_append("A vector_now=" .. tostring(now) .. " handler=" .. tostring(h) ..
                       " shcsr_after=" .. tostring(shcsr))
            -- mt_handler 本身就是带 Thumb 位的函数指针（奇数），向量写的就是它，
            -- 所以"相等"才是成功；不相等说明向量没被我们改掉。
            if now and h and now ~= h then
                ARM.stop = "关A 失败：向量仍是 " .. tostring(now) .. "（应为 " .. tostring(h) .. "）"
            end
        elseif tag == "B" then
            if reason == "memmanage_escalated" or reason == "flash_preflight_failed"
               or reason == "memmanage_not_delivered" or reason == "mpu_enable_refused" then
                ARM.stop = "关B 失败：" .. reason
            end
        elseif tag == "C1" then
            -- 只布防、不产生故障。这里若不对，绝不能进 C2。
            if reason ~= "region_armed_no_fault_yet" then
                ARM.stop = "关C1 失败：区域没装上（" .. reason .. "）"
            end
        elseif tag == "C2" then
            if reason ~= "armed_ok" then
                ARM.stop = "关C2 失败：" .. reason
            end
        end
        return true
    end
end

local arm_steps = {
    function()
        local out = sh_out("cat /dev/tunentry")
        local addr = field_of(out, "mt_cmd_addr")
        if not addr then
            return false, "没读到 mt_cmd_addr：模块没在内存里跑。先按①加载（刚换过模块要先重启再按①）"
        end
        local run = field_of(out, "mt_build")
        if run ~= MODULE_BUILD then
            return false, "内存里跑的不是这一版模块（" .. tostring(run) .. " ≠ " .. MODULE_BUILD ..
                          "）：请按① → 重启 → 再按① ，然后才按③"
        end
        ARM.addr = addr
        ARM.files = {}
        ARM.stop = nil
        write_all("/data/mt-0.txt", out)
        log_append("mt_cmd_addr=" .. addr)
        set_status("布防 关A…", 0xFFD60A)
        return true
    end,
    arm_stage("1", "A"),
    arm_stage("2", "B"),
    arm_stage("3", "C1"),
    arm_stage("4", "C2"),
    function()
        local out = sh_out("cat /dev/tunentry")
        write_all("/data/mt-final.txt", out)
        local state = field_of(out, "mt_state") or "?"
        local hook = field_of(out, "system_dns_hook") or "?"
        local hits = field_of(out, "mt_cache_hits") or "?"
        local subs = field_of(out, "mt_subst_ok") or "?"
        log_append("final mt_state=" .. state .. " system_dns_hook=" .. hook ..
                   " hits=" .. hits .. " subst_ok=" .. subs)
        ok_note = "布防结束 mt_state=" .. state .. " hook=" .. hook ..
                  "\n报告 /data/mt-A|B|C|final.txt"
        return true
    end,
}

-- ============ socket 自检（按钮④）============
-- 链路：读 /dev/tunentry 取 mt_cmd_addr → `mw <addr>=16` 下发自检 →
-- 读 /dev/tunsvc 触发命令执行（模块在 lpwork 里依次跑
--   socket / setsockopt(0xa,16B) / setsockopt(0xe,16B) / bind(0.0.0.0:53167) /
--   recv(NULL)对照 / recvfrom(&from,16)）→ 隔 ~100ms 再读一次取结果。
-- 判定：st5_rc>0 或 st5_errno=11(EAGAIN) ⇒ 收包口完全正常；107/97/22 各自对应已知坑。
local SELF = { addr = nil, before = "0" }

local function self_field(out, key)
    return field_of(out, key) or "?"
end

local self_steps = {
    function()
        -- 基线：先读一次 tunsvc（顺带执行可能残留的 mw），记下自检完成计数
        local out = sh_out("cat /dev/tunsvc")
        SELF.before = self_field(out, "st_self_n")
        return true
    end,
    function()
        local out = sh_out("cat /dev/tunentry")
        local addr = field_of(out, "mt_cmd_addr")
        if not addr then
            return false, "没读到 mt_cmd_addr：模块没在内存里跑。先按①加载（刚换过模块要先重启再按①）"
        end
        local run = field_of(out, "mt_build")
        if run ~= MODULE_BUILD then
            return false, "内存里跑的不是这一版模块（" .. tostring(run) .. " ≠ " .. MODULE_BUILD ..
                          "）：请按① → 重启 → 再按① ，然后才按④"
        end
        SELF.addr = addr
        log_append("socket 自检：mt_cmd_addr=" .. addr .. "，下发 mw " .. addr .. "=16")
        set_status("自检：已下发，等模块跑完 6 步…", 0xFFD60A)
        sh("mw " .. addr .. "=16")
        return true
    end,
    function() sh_out("cat /dev/tunsvc"); return true end,   -- 触发命令执行
    function() sh_out("cat /dev/tunsvc"); return true end,   -- 等一拍
    function()
        local out = sh_out("cat /dev/tunsvc")
        if type(out) ~= "string" or #out < 64 then
            return false, "读 /dev/tunsvc 失败"
        end
        write_all("/data/mt-self.txt", out)
        local n  = self_field(out, "st_self_n")
        local r0, e0 = self_field(out, "st0_rc"), self_field(out, "st0_errno")
        local r1, e1 = self_field(out, "st1_rc"), self_field(out, "st1_errno")
        local r2, e2 = self_field(out, "st2_rc"), self_field(out, "st2_errno")
        local r3, e3 = self_field(out, "st3_rc"), self_field(out, "st3_errno")
        local r5, e5 = self_field(out, "st5_rc"), self_field(out, "st5_errno")
        if n == SELF.before and tostring(SELF.before) ~= "?" then
            set_status("自检还没跑完（n 未变）\n稍等 1 秒再按一次④即可", 0xFFD60A)
            return true
        end
        -- v60 起自检形状 = socket→超时→bind→connect→recvfrom(from=NULL)
        local c4, ec4 = self_field(out, "st4_rc"), self_field(out, "st4_errno")
        local verdict
        if r5 ~= "0xffffffff" and r5 ~= "?" then
            verdict = "收包口 OK（真收到数据 " .. r5 .. "B，st4=1 表示缓冲区被改写）"
        elseif e5 == "11" then
            verdict = "收包口 OK（EAGAIN=暂无回包，正常）"
        elseif e5 == "101" then
            verdict = "收包口 OK（ENETUNREACH=手机/网络还没起）"
        elseif e5 == "107" then
            verdict = "ENOTCONN —— 形状不对（疑似又调成了 sendto 那条）"
        elseif e5 == "22" then
            verdict = "recvfrom 参数被拒（EINVAL）—— 形状不对"
        else
            verdict = "看 st5_errno"
        end
        log_append("自检 n=" .. n .. "（基线 " .. tostring(SELF.before) .. "）" ..
                   " socket=" .. r0 .. "/" .. e0 ..
                   " rcvto=" .. r1 .. "/" .. e1 ..
                   " sndto=" .. r2 .. "/" .. e2 ..
                   " bind=" .. r3 .. "/" .. e3 ..
                   " recvfrom=" .. r5 .. "/" .. e5 ..
                   " → " .. verdict)
        ok_note = "socket 自检 n=" .. n ..
                  "\nsocket fd rc=" .. r0 .. " errno=" .. e0 ..
                  "\nrcvto rc=" .. r1 .. " sndto rc=" .. r2 ..
                  "\nbind rc=" .. r3 .. " errno=" .. e3 ..
                  "\nrecvfrom rc=" .. r5 .. " errno=" .. e5 ..
                  "\n" .. verdict .. "\n报告 /data/mt-self.txt"
        return true
    end,
}

-- ============ 注入式收包自检（按钮⑤）============
-- 模块自己造一条 DNS 回包，从**手机同一个入口**（NETDEV_INPUT → IPV4_CALLBACK）注入协议栈，
-- 再用 socket 收回来、消费、写缓存 ⇒ 一条命令验完"除手机转发以外"的整条 RX 链。
local inj_steps = {
    function()
        local out = sh_out("cat /dev/tunentry")
        local addr = field_of(out, "mt_cmd_addr")
        if not addr then return false, "没读到 mt_cmd_addr：模块没在内存里跑（先①、重启、再①）" end
        local run = field_of(out, "mt_build")
        if run ~= MODULE_BUILD then
            return false, "内存里跑的不是这一版模块（" .. tostring(run) .. " ≠ " .. MODULE_BUILD .. "）"
        end
        log_append("注入自检：mw " .. addr .. "=17")
        set_status("注入自检：已下发（造回包→注入→收→验缓存）…", 0xFFD60A)
        sh("mw " .. addr .. "=17")
        return true
    end,
    function() sh_out("cat /dev/tunsvc"); return true end,
    function() sh_out("cat /dev/tunsvc"); return true end,
    function() sh_out("cat /dev/tunsvc"); return true end,
    function()
        local out = sh_out("cat /dev/tunsvc")
        if type(out) ~= "string" or #out < 64 then return false, "读 /dev/tunsvc 失败" end
        write_all("/data/mt-inj.txt", out)
        local n  = self_field(out, "inj_n")
        local bl = self_field(out, "inj_build")
        local rr = self_field(out, "inj_recv_rc")
        local se = self_field(out, "inj_sentinel")
        local co = self_field(out, "inj_consume")
        local ip = self_field(out, "inj_cache_ip")
        log_append("注入自检 n=" .. n .. " 帧长=" .. bl .. " recv=" .. rr ..
                   " sentinel=" .. se .. " consume=" .. co .. " cache_ip=0x" .. ip)
        local verdict
        if ip == "0x5db8d822" or ip == "5db8d822" then
            verdict = "★★ 全链路打通：回包被协议栈按端口投递 → socket 收到 → 校验通过 → 写进缓存"
        elseif se ~= "1" then
            verdict = "socket 没收到真数据（sentinel 未被改写）——查 sd_* / inj_recv_rc"
        elseif co ~= "2" then
            verdict = "收到但校验没过（ID 环 / 问题名）——查 ign_id / ign_qname"
        else
            verdict = "消费成功但缓存没命中（cache_ip=0）"
        end
        ok_note = "注入自检 n=" .. n .. "\n帧长=" .. bl .. " 收到=" .. rr ..
                  "\nsentinel=" .. se .. " consume=" .. co .. "\ncache_ip=0x" .. ip ..
                  "\n" .. verdict .. "\n报告 /data/mt-inj.txt"
        return true
    end,
}

-- ★ 一步到位：把「分级布防」并进按钮①。DNS 要生效必须布防，不能靠人记得再点一次。
--   ① = 切资源 → 写模块 → insmod tun → 校验版本 → 装证书模块 → 读 mt_cmd_addr → 布防 1/2/3
do
    local i
    for i = 1, #arm_steps do
        load_steps[#load_steps + 1] = arm_steps[i]
    end
end

local rootbase = lvgl.Object(nil, {
    w = W, h = H, outline_width = 0, border_width = 0, pad_all = 0,
    bg_color = 0x000000, bg_opa = lvgl.OPA(100),
})
rootbase:clear_flag(lvgl.FLAG.SCROLLABLE)

lvgl.Label(rootbase, {
    text = "TUN 模块", align = { type = lvgl.ALIGN.CENTER, x_ofs = 0, y_ofs = -190 },
    text_color = 0xFFFFFF, text_font = lvgl.Font("MiSans-Demibold", 32),
})
lvgl.Label(rootbase, {
    text = "加载模块 / 自启动管理", align = { type = lvgl.ALIGN.CENTER, x_ofs = 0, y_ofs = -156 },
    text_color = 0x9DB7D8, text_font = lvgl.Font("MiSans-Regular", 18),
})

local panel = lvgl.Object(rootbase, {
    w = 304, h = 146, bg_color = 0x101820, bg_opa = lvgl.OPA(100),
    radius = 14, border_width = 1, border_color = 0x244566,
    pad_left = 14, pad_right = 14, pad_top = 10, pad_bottom = 10,
    align = { type = lvgl.ALIGN.CENTER, x_ofs = 0, y_ofs = 128 },
})
panel:clear_flag(lvgl.FLAG.SCROLLABLE)
status = lvgl.Label(panel, {
    text = "1 加载+布防（tun+证书+DNS）\n2 写入开机自启\n3 移除自启\n\n装完自启后去管理器：\n[3 模块管理] → [2 重建自启动]\n\n日志 " .. LOGPATH,
    text_color = 0xB3B3B3, width = 276, height = 126,
    text_font = lvgl.Font("MiSans-Regular", 18),
    align = { type = lvgl.ALIGN.TOP_LEFT, x_ofs = 0, y_ofs = 0 },
})

local function make_button(text, y, color, on_clicked, w, x, fs)
    w = w or 304
    x = x or 0
    fs = fs or 20
    local button = lvgl.Object(rootbase, {
        w = w, h = 40, bg_color = color, bg_opa = lvgl.OPA(100),
        radius = 16,
        align = { type = lvgl.ALIGN.CENTER, x_ofs = x, y_ofs = y },
    })
    button:clear_flag(lvgl.FLAG.SCROLLABLE)
    button:add_flag(lvgl.FLAG.CLICKABLE)
    lvgl.Label(button, {
        text = text, text_color = 0xFFFFFF, align = lvgl.ALIGN.CENTER,
        text_font = lvgl.Font("MiSans-Regular", fs),
    })
    button:onClicked(function()
        local ok, message = pcall(on_clicked)
        if not ok then set_status("Error: " .. tostring(message), 0xFF9A9A) end
    end)
    return button
end

load_button = make_button("1 加载+布防（DNS 生效）", -120, 0x14508A, function()
    start_action(load_steps)
end)
rc_button = make_button("2 写入开机自启", -74, 0x1E4D8C, function()
    start_action(rc_steps)
end)
rm_button = make_button("3 移除自启", -28, 0x1F5FA8, function()
    start_action(rm_steps)
end)

early_write("/data/tunboot-3.txt", "ui built\n")
