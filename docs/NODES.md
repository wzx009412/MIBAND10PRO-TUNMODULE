# 节点与命令

模块注册三个节点（v108 起；旧版还有 `tunstat` / `tunresolve`，已删除）。

| 节点 | 权限 | 读 | 写 |
|---|---|---|---|
| `/dev/tun` | 0666 | 协议栈收包 | 协议栈发包 |
| `/dev/tunentry` | 0666 | 状态页（arming 必需字段 + 诊断）| 下发命令 |
| `/dev/tunsvc` | 0444 | 诊断页（**默认只回一行**）| — |

`tunentry` 同时承担 `tunstat` 的读职责——**一个节点够用**，所以把 `tunstat` 摘了。

---

## 1. 命令（写 `/dev/tunentry`）

```sh
echo 3 > /dev/tunentry      # 下发命令 3
cat /dev/tunentry > /dev/null   # ★ 必须读一次才会执行
```

> 写只把命令放进 `g_mt_cmd`；`mt_cmd_poll()` 在**读节点**或**周期服务**里才评估。
> 所以「写完不读」= 命令永远不执行。

| # | 作用 |
|---|---|
| 1 | 装双向量 + 使能 MEMFAULTENA |
| 2 | 开 MPU + 闪存预检 + 合成陷阱往返自检 |
| **3** | **真正布防解析器窗口**（DNS 从这一步开始生效）|
| **4** | 替换路径验证 |
| 5 / 6 | 解除布防 / 清 fault |
| 7 | 清解析缓存 |
| 8 | `mt_arm()` 一次跑完整阶梯 |
| 9 / 10 | 慢路径 开 / 关 |
| 11 | 一键清空（缓存 + 待解析队列 + abort）|
| 12 / 13 | 信号量 ABI 自检 / 阻塞对照实验 |
| 14 / 15 | socket 传输 切换 / 复位 |
| 16 / 17 / 18 | socket 自检 / 注入式收包自检 / TCP-DNS 自检 |
| 19 | 手动注册 netdev（唯一碰 registrar 的命令）|
| 20 / 21 | 宿主桥喂回包 / 查指定域名（模拟器用）|
| 22 | IOB 池扩容 24→88 |
| 23 | 装固定测试租约（10.1.10.2）|
| 24 | 真栈注入（NETDEV_INPUT）|
| 25 / 26 | `iob_navail` 探测 / 装 +64 钩子 |
| **97** | **关完整日志**（`/dev/tunsvc` 只回一行）|
| **98** | **开完整日志** |

**布防顺序固定 `1 → 2 → 3 → 4`**，每一步都要读一次节点。跳步或乱序 ⇒ DNS 不生效。

---

## 2. 日志总闸：默认关

`/dev/tunsvc` 完整页约 **3.5 KB、200 个字段**，而且是在 `NET_LOCK` 里格式化出来的——
每读一次就阻塞网络路径一次。生产环境不需要它。

| 状态 | `/dev/tunsvc` 返回 |
|---|---|
| 默认（关）| 一行版本 + `dbg=off` + `mt_build` + `mt_armed/netdev_ready/dns_*` 五个计数 |
| `echo 98 > /dev/tunentry` 后 | 完整诊断页（`mt_end=1` 结尾）|
| `echo 97 > /dev/tunentry` 后 | 回到短页 |

开关是**纯内存标志**，模块内部**不碰文件系统**（原因见 [PITFALLS](PITFALLS.md#1)）。

### 「有没有 `/data/tundebug`」由谁判断

**自启动脚本**，用 nsh 的单层 `[ -f ]`：

```sh
if [ -f /data/tundebug ];then
echo 98 > /dev/tunentry
fi
```

想临时开日志：

```sh
echo x > /data/tundebug     # 建文件
echo 98 > /dev/tunentry     # 立刻打开（不必重启）
```

---

## 3. 读状态时看什么

`cat /dev/tunentry` 里和 DNS 相关的关键字段：

| 字段 | 正常 | 说明 |
|---|---|---|
| `mt_armed` / `mt_state` | 1 / ≥3 | 布防完成 |
| `netdev_ready` | 1 | bt-net 网卡已注册并被协议栈接管 |
| `dhcp_state` / `ip_configured` | 6 / 1 | 租约拿到（10.1.10.2）|
| `dns_raw_le` | `0x72727272` | = 114.114.114.114（手机下发的）|
| `dns_queries` / `dns_sent` / `dns_replies` | 递增 | 拦截 → 发出 → 收到回包 |
| `sd_en` | 0 | socket 传输默认关；`dns_sent` 走 raw 分支 |
| `ioctl_n` / `ioctl_728` | >0 | 说明有 app 真正发了网络请求 |

`ioctl_n=0` 的含义很明确：**自本次 insmod 起没有任何应用发起过网络请求**，
模块只是在等人上门——不是模块坏了。
