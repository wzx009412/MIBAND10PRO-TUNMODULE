# tunboot 表盘

三个按钮，把 tun + 证书装好，并把自启动脚本投给 `10pro.autorun` 管理器。

| 按钮 | 作用 |
|---|---|
| **① 加载+布防（DNS 生效）** | 写 tun 模块 → `insmod` → 校验 `mt_build` → 装 capatch+ca.pem → 读 `mt_cmd_addr` → 布防 1→2→3→4 |
| **② 写入开机自启** | 投 `/data/rc.d/tun.sh`（首行 `# top`）；没有 `/data/rc.d` 就报错且零写盘 |
| **③ 移除自启** | 只删 `/data/rc.d/tun.sh`，不动 `/data/rc`、不动闸、不动主功能文件 |

## 资源槽位

`_Lua/shellpp_ii-3.101.043.bin` 是四段拼接体，**长度写在 `main.lua` 顶部**：

```
[0        .. 74640)   tun-3.101.043.bin
[74640    .. 298324)  CA bundle（223684，旧方案遗留，当前不再使用）
[298324   .. 306384)  capatch.elf（8060）
[306384   .. 310422)  ca.pem（4038）
```

偏移由长度**推导**（`CAP_OFF = MODULE_SIZE + CA_SIZE`），不要硬编码。

## 工具

```bash
PY="C:/Users/Administrator/.workbuddy/binaries/python/envs/default/Scripts/python.exe"

$PY tools/_pack_blob.py                   # 从零件拼资源槽位（校验每段长度+md5）
$PY tools/_sim_rc.py                      # 离线行为门 19 条
$PY tools/_rebuild_resource.py            # 改完 _Lua/ 后重建 resource.bin
$PY tools/pack_mwz.py --out ../dist/tunboot_cert.face   # 打包 + 19 条结构门
```

## 从零重建整条链

```bash
python modules/tun/build.py               # → modules/tun/build/tun-3.101.043.bin
python modules/capatch/build_capatch.py   # → modules/capatch/capatch.elf
python face/tools/_pack_blob.py           # 拼 _Lua/shellpp_*.bin
cp face/_Lua/main.lua face/resources/_lua/_Lua/main.lua
python face/tools/_rebuild_resource.py
python face/tools/pack_mwz.py --out face/../dist/tunboot_cert.face
```

`_pack_blob.py` 的四段来源：`--tun`（build.py 产物）、旧 CA 段（默认从现有槽位抠）、
`--capatch`、`--pem`（默认 `assets/ca.pem`，4,038 B 证书链）。
任一段长度或 md5 与 `main.lua` 常量不符 ⇒ **一个字节都不写**。

## 换模块时的清单

1. 改 `modules/tun/src` → `build.py` → 新 `tun-*.bin`
2. 重拼 `_Lua/shellpp_ii-3.101.043.bin`（四段）
3. 改 `main.lua` 的 `MODULE_SIZE` / `MODULE_BUILD`
4. `_sim_rc.py` + `pack_mwz.py` 两道门全绿
