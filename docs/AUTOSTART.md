# 自启动：契约与脚本

本项目的自启动**不自己写 `/data/rc`**，而是按 `10pro.autorun` 管理器的注册契约
（`REGISTER.md` v0.6.6）投一片脚本进 `/data/rc.d/`。

---

## 1. 职责边界（管理器的硬要求）

| 归谁 | 内容 |
|---|---|
| **模块**（本项目）| 只写「自己要跑的命令」→ `/data/rc.d/tun.sh` |
| **管理器** | 闸 `/data/rc.d/.autorun.on`、心跳 `.autorun.log`、两个安全窗口（`sleep 8` / `sleep 15`）、`/data/rc` 的生成 |

所以我们的脚本里：

- ❌ 没有 `if [ -f ...autostart.on ]`（那是模块自己的闸，新规范已废弃）
- ❌ 没有 `sleep`（窗口归管理器，模块各带一份会 N 倍叠加）
- ❌ 不碰 `/data/rc`、不碰 flash
- ✅ 只有 `insmod` / `echo` / `cat` / 一条 `[ -f ]`

没有 `/data/rc.d` 时**必须报错退出、零写盘**——不许自己 `mkdir`（否则用户以为装好了，
开机什么都不发生）。

---

## 2. 投出去的脚本

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
echo 2 > /dev/tunentry
cat /dev/tunsvc > /data/tun/arm2.txt
echo 3 > /dev/tunentry
cat /dev/tunsvc > /data/tun/arm3.txt
echo 4 > /dev/tunentry
cat /dev/tunsvc > /data/tun/arm4.txt
if [ -f /data/tundebug ];then
echo 98 > /dev/tunentry
fi
echo armed >> /data/tun/autostart.log
echo done >> /data/tun/autostart.log
```

### 逐段说明

| 段 | 为什么这么写 |
|---|---|
| `# top` | 标记行；nsh 当注释，不影响执行 |
| `insmod ... tun` | 模块名必须 `tun`（`/dev/tun` 的节点名与它绑定）|
| `echo N > /dev/tunentry` | 模块 v74 起支持**流式命令**，不需要 `mt_cmd_addr`（那个地址每次开机都变，nsh 解析不了）|
| `cat /dev/tunsvc > armN.txt` | 写只是入队；**读节点才触发 `mt_cmd_poll()`**。顺带把当时的完整状态落盘留证 |
| `if [ -f /data/tundebug ]` | 单层 if，和管理器生成的 `if [ -f ... ]` 同形，规避 nsh 嵌套风险 |
| `echo armed` / `echo done` | 末行是 `done` ⇒ 整段跑完；停在 `armed` 之前 ⇒ 布防中途出事 |

### 两个「不许」

- **不许** `cat 某个文件 > /dev/tunentry`：nsh 的 `cat` 写设备是 **4 字节步长散开**的
  （`entry_head = 6d 00 00 00 74 …`，`'m'@0`、`'t'@4），解析器永远拼不齐。**只能用 `echo`**。
- **不许**在脚本里加 `sleep`：闸与窗口是管理器的职责。

---

## 3. 装完还要按一下管理器

投脚本**不会**自动改 `/data/rc`：

```
装上表盘 → 按② 写入开机自启 → 打开 10pro.autorun
        → [3 模块管理] → [2 重建自启动]
```

`[2 重建自启动]` 之后 `/data/rc` 里才会出现 `sh /data/rc.d/tun.sh` 那一行。
状态行会亮 `● 待重建` 提示。

### 移除

表盘按钮 **③ 移除自启** 只删 `/data/rc.d/tun.sh`，**不动** `/data/rc`、不动闸，
也不会碰主功能文件（tun 模块 / capatch / ca.pem）。
同样要去管理器按 `[2 重建自启动]`，那一行才会消失。

---

## 4. 开机后怎么判

```
cat /data/tun/autostart.log      # 末行 done ⇒ 跑到底
cat /data/tun/arm4.txt           # 找 mt_armed=1
cat /dev/tunentry | grep mt_armed
```

| 现象 | 含义 |
|---|---|
| 没有 `autostart.log` | 脚本压根没跑：管理器没装好 / 没按 `[2 重建自启动]` / flash 里的 rcS hook 不在 |
| 末行是 `armed` 或更早 | 布防中途出事，看 `armN.txt` 是哪一步停的 |
| 末行 `done` 但 `mt_armed=0` | 命令没被执行——检查是不是用了 `cat` 写节点，或漏了 `cat` 触发 |
| `mt_armed=1` 但 DNS 不通 | 布防好了，问题在 DHCP/应用侧：看 `ioctl_n` 是否为 0 |
