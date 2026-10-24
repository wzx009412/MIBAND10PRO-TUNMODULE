# MIBAND10PRO-TUNMODULE

小米手环 10 Pro（p67tc，固件 3.101.043 / openvela-NuttX）上的**两个内核模块 + 一张表盘**：

| 组件 | 作用 |
|---|---|
| **tun 模块** | 自建 `bt-net` 网卡，接管应用 DNS，把查询经 BLE 送到手机，由手机 App 代发 |
| **capatch 模块** | 往 libcurl 真正使用的全局 CA 链里塞根证书，修好 HTTPS 校验失败（code 60） |
| **tunboot 表盘** | 一键装好上面两个（含布防），并把开机自启脚本投给 `10pro.autorun` 管理器 |

> **前提**：本机没有 WiFi。应用的所有网络请求都走
> `quickapp → app_net → /dev/tun → BLE → 手机 libnetproxy → 公网`，
> 手机侧看到的是 BLE 流量，不是 IP。

---

## 1. 它做了什么

```
┌──────────── 手表 ────────────┐        ┌──── 手机 ────┐
 quickapp fetch
   → app_net (0x0C71132C)      │        │              │
     open("/dev/tun", 0x403)   │        │              │
     ioctl(0x728, "bt-net")    │──────▶ │  libnetproxy │
   → tun 模块注册 netdev       │  BLE   │  chk_dhcp    │
   → DHCP → 10.1.10.2/24       │        │  → 10.1.10.2 │
   → DNS 查询被拦截             │        │  gw 10.1.10.1│
   → 走 TUN 出到 BLE            │        │  DNS 114.114.114.114
                               │        │  → 公网      │
└──────────────────────────────┘        └──────────────┘
```

两条独立的修复：

- **DNS**：`tun` 模块拦截解析器入口（MPU + 向量表 + 窗口布防），把 `getaddrinfo` 变成
  「模块自己发 DNS 查询 → 等手机回包 → 写缓存 → 返回」。
- **HTTPS**：`capatch` 模块直接往固件里 libcurl 的全局 CA 链（`*(0x20103594)`）追加
  证书；链不存在时自己 `malloc(0x154)` + `x509_crt_init` 建一条。
  这**不是** `-k`，校验照常进行，只是把 CA 补回去。

---

## 2. 目录

```
face/                 tunboot 表盘工程（Lua + 资源 + 打包/校验工具）
  _Lua/main.lua       表盘逻辑：3 个按钮 + 自启脚本生成
  _Lua/shellpp_*.bin  资源槽位 = [tun 74640][CA 223684][capatch 8060][ca.pem 4038]
  tools/              pack_mwz.py（打包+19 条门）/ _sim_rc.py（离线行为门 19 条）
modules/tun/          bt-net 网卡 + DNS 拦截模块（C，裸机 freestanding）
modules/capatch/      CA 链注入模块（C）
dist/                 成品 tunboot_cert.face
docs/                 节点/自启/踩坑/历史 README
```

---

## 3. 装机（三步）

1. 装 `dist/tunboot_cert.face`
2. 按 **① 加载+布防**（装 tun、装证书、布防 1→2→3→4，一次跑完）
3. 按 **② 写入开机自启** → 打开 `10pro.autorun` → `[3 模块管理]` → `[2 重建自启动]`

> **换过模块后必须先重启再按①**：内存里跑的旧版会被 `mt_build` 版本校验拦住（设计如此）。

开机后自启脚本 `/data/rc.d/tun.sh` 会长这样：

```sh
# top
set +e
echo start > /data/tun/autostart.log
insmod /data/tun/tun-3.101.043.bin tun
echo tun >> /data/tun/autostart.log
insmod /data/ssl/capatch.elf capatch
echo cert >> /data/tun/autostart.log
echo 1 > /dev/tunentry
cat /dev/tunsvc > /data/tun/arm1.txt
...（2/3/4 同上）
if [ -f /data/tundebug ];then
echo 98 > /dev/tunentry
fi
echo armed >> /data/tun/autostart.log
echo done >> /data/tun/autostart.log
```

---

## 4. 三个节点

| 节点 | 权限 | 用途 |
|---|---|---|
| `/dev/tun` | rw | 数据通道（应用/协议栈用，别手动碰）|
| `/dev/tunentry` | rw | **唯一调试口**：`cat` 读状态，`echo <n> >` 下发命令 |
| `/dev/tunsvc` | ro | 日志/诊断页；**默认只回一行** |

命令表、日志开关、以及为什么日志默认关，见 [docs/NODES.md](docs/NODES.md)。

---

## 5. 验证

```bash
PY="C:/Users/Administrator/.workbuddy/binaries/python/envs/default/Scripts/python.exe"

# 离线行为门（19 条：投脚本/幂等/移除/不碰别人的文件/资源长度/布防序列/调试开关）
$PY face/tools/_sim_rc.py           # 期望 SIM-RC: PASS (19)

# 打包 + 19 条结构门
$PY face/tools/pack_mwz.py --out dist/tunboot_cert.face
                                    # 期望 PACK-MWZ: PASS (19)
```

真机验证：

```
cat /dev/tunentry | grep -E "mt_armed|mt_state|netdev_ready"
cat /dev/tunsvc   | grep -E "dns_queries|dns_sent|dns_replies"
```

`mt_armed=1` 且 `dns_sent>0` ⇒ DNS 链路起来了。

---

## 6. 已知限制

- 布防必须 **1→2→3→4** 顺序，缺一步 DNS 就不生效（③ 在表盘里已并入①）。
- 布防在 QEMU 模拟器里会挂（MPU/向量操作模拟器不支持），**只能在真机验**。
- 自启脚本**只负责 insmod + 布防**，DHCP 仍需应用真正发一次请求（`ioctl 0x728`）才触发。
- 换模块必须同步改 `MT_BUILD`（`modules/tun/src/mpu_trap.h`）和表盘的 `MODULE_BUILD`。

踩过的坑（会吃掉整晚的那种）见 [docs/PITFALLS.md](docs/PITFALLS.md)。

---

## 7. 范围

本项目只做**本机网络可用性修复**（补 CA、修 DNS 路径），不修改固件、不写 flash、
不降低 TLS 校验强度。

---

## 8. 发布

仓库里**保留成品**（`dist/`），同时**每个版本发一个 Release**，附件就是同一个 `.face`。

发版三步（远端还没加时先 `git remote add origin <url>`）：

```bash
git push -u origin master --tags
# 然后网页：Releases → Draft a new release → 选 tag v108
#   Title: v108 — tun 模块 + CA 修补 + 自启动表盘
#   Body : 直接粘贴 RELEASE_NOTES.md
#   Assets: dist/tunboot_cert.face（以及 dist/tunboot_cert.face.md5）
```

有 `gh` 的话一条命令：

```bash
gh release create v108 dist/tunboot_cert.face dist/tunboot_cert.face.md5 \
  --title "v108 — tun 模块 + CA 修补 + 自启动表盘" --notes-file RELEASE_NOTES.md
```
