# v108

小米手环 10 Pro（p67tc / 固件 3.101.043）网络修复包：**tun 模块 + CA 修补 + 自启动表盘**。

## 安装

1. 装 `tunboot_cert.face`
2. 按 **① 加载+布防**
3. 按 **② 写入开机自启** → 打开 `10pro.autorun` → `[3 模块管理]` → `[2 重建自启动]`

> 换过模块要**先重启再按①**（版本校验会拦住内存里的旧模块）。

## 自检

```
cat /data/tun/autostart.log                                   # 末行 done
cat /dev/tunentry | grep -E "mt_armed|netdev_ready"
cat /dev/tunsvc   | grep -E "dns_queries|dns_sent|dns_replies"
```

`mt_armed=1` 且 `dns_sent>0` ⇒ 链路通了。

## 校验

`tunboot_cert.face` md5 `2e7e3f671d1db0d99e02ecbb2d4c6ea1`

不修改固件、不写 flash、不降低 TLS 校验强度。
