# 打成单个可执行文件

## 2026-11-27 客户端适配

v0.1.4 的 Release 附件只提供 Windows x64 EXE。公开源码不包含 `rsa_modulus.json`、
客户端文件、私钥、会话密钥或抓包；`rsa_modulus.json` 保留在本机并在构建时嵌入 EXE。
下载源码后不能直接复现完整打包，需自行准备与客户端匹配的本地材料。
EXE 内只含解码所需的公钥模数，客户端私钥仍由运行时读取用户本机客户端。

当前绑定 DLL SHA-256 `92a1dc8de00d43a18b62f4042f5d87df8a069d71ea9a71762c97677451a9e616`、
metadata SHA-256 `37c838f5ec9f5bee914b2b88b0ea7684a1b61b87b1cf13d5fd5d86b9778d794f`。
RSA 字符串引用更新为 RVA `0xF118E28`（literal 15813）。既有公钥模数经过新版真实登录握手、
连续流及移动消息验证后沿用，没有通过跳过版本校验来兼容。

本次本地样本包含 2292 个 TCP 包、218 条移动消息、520 条对象位置、158 条主控位置；
正常回放和乱序加重复包回放结果一致。工厂快照读出 3685 个节点、599 条线路，滑索快照
读出 226 个节点，两者均无解析错误；尚未逐项对照游戏内设施。场景名称表未重新导出，
新版新增或修改的场景名称不在本次验证范围内。

**当前版本必须携带匹配的 `data/rsa_modulus.json`。** `srsa.py` 中的历史模拟入口尚未适配，
缺少数据时会明确报错，`generate_rsa_modulus.py` 也不能直接用于此版本。
下文关于模拟恢复的说明是历史流程，需先重新定位并验证原生入口后才能使用。

给不装 Python 的机器用的打包方式。**当前状态：可构建、可启动，且能在冻结进程里跑完整个
解码链路**（`selftest` 回放与 `serve` 输出坐标都与源码环境逐项一致）。

```bash
uv run --with pyinstaller pyinstaller packaging/endfield-capture-backend.spec --noconfirm
```

产物 `dist/endfield-capture-backend.exe`（onefile，19.2 MB）。跑法跟命令行版一样：

```powershell
.\endfield-capture-backend.exe serve --no-dashboard          # 只留 /api/*
.\endfield-capture-backend.exe serve --pipe --no-http         # 零端口：只推命名管道
.\endfield-capture-backend.exe selftest <pcap> --game-dir <客户端目录>
```

## 体积

| 形态 | 大小 |
|---|---|
| onefile exe（当前） | 19.2 MB |
| 同一份 spec 在去掉 `unicorn` / `capstone` 之前 | 23.9 MB |
| 对照：`uv sync` 出的 venv | 99 MB |

大头是 `scapy`、`cryptography`、`pycryptodome`、`protobuf`。spec 里已经把 GUI / 科学计算
那一堆排除掉了。

> venv 里 `unicorn` + `capstone` 合计 69.1 MB，但那不等于冻结产物里的体积——PyInstaller 会
> 压缩，且这两个包的份量大多在测试与开发文件上。真正省下来的是 **4.7 MB**，顺带把下面那个
> JIT 崩溃问题一并解决。

## 打不进去、必须单独准备的东西

- **Npcap 驱动**：抓包必需（安装时勾 "WinPcap API-compatible Mode"）。驱动不是 Python 包，
  只能装到目标机器上；**没有它，程序能起但抓不到包**。构建日志里那条
  `Library wpcap.dll required via ctypes not found` 就是它，属正常。
- **游戏客户端**：`GameAssembly.dll` 与 `global-metadata.dat` 只从本机客户端读
  （`--game-dir` 或 `EF_GAME_DIR`），二进制里不含游戏文件。
- **ok-end-field**：只有启用官方地图 WS 对照时才需要；配合本二进制一般用 `--no-map-ws`
  （冻结版带不了 ok-script 依赖）。

两份运行时数据**随包带**，不用额外准备：

| 文件 | 用途 |
|---|---|
| `data/scene_index.json` | 场景号 → 关卡 / 中文名 / 副本 / 大地图 |
| `data/rsa_modulus.json` | 恢复登录响应所需的公钥模数，见下 |

## 为什么冻结版不带 `unicorn` / `capstone`

这两个包只服务 `endfield_capture.srsa` 那个离线模拟器：首次登录响应时把客户端 DLL 的机器码
跑一遍，恢复出 2048 位公钥模数。问题在于 **unicorn 的 JIT 在 PyInstaller 冻结出的进程里会
直接崩掉**——`0xC0000409`（STATUS_STACK_BUFFER_OVERRUN），连 Python traceback 都没有。用最小
探针把范围缩到了 `uc.emu_start`，与 onefile / onedir 无关，也不是 DLL 没收集进来。

模数只跟客户端版本有关，而客户端版本已经被 SHA-256 钉死，所以可以像场景表一样**离线解一次、
存成数据**：

1. `tools/generate_rsa_modulus.py` 跑一次模拟器，把 `{客户端哈希, modulus}` 写进
   `data/rsa_modulus.json`；
2. 运行时 `Bootstrap` 先查这份数据（哈希对得上就用，**完全不碰模拟器**），对不上再回退模拟器；
3. 于是冻结版只带数据，不再需要 `unicorn` / `capstone`。

重新生成（客户端更新后要做，需要一份**含登录握手**的完整抓包）：

```bash
python tools/generate_rsa_modulus.py                       # 自动取 runs/ 里最新的一份抓包
python tools/generate_rsa_modulus.py --pcap <路径>          # 指定抓包
python tools/generate_rsa_modulus.py --dry-run             # 只打印，不写文件
```

脚本自带三道闸：两次模拟（懒恢复 vs 独立重跑）结果必须一致、模数必须是 2048 位、
纯 Python 模幂输出必须与模拟输出逐字节相同。任何一条不过就拒绝写文件。

源码环境仍然可以走模拟器那条路（装了 unicorn 才有），所以数据缺失不会静默解出错东西
——程序会明确报「这条客户端没有可用的预存模数，而本程序不含模拟器」。

## 无界面模式

`--no-dashboard` 只是**不提供**看板，页面本身仍然打在包里（17 KB，见 `static/dashboard.html`）——
不加这个参数时 `GET /` 正常出看板。之所以之前不带它，是 spec 的 `datas` 漏了那个文件，而
`server.py` 是直接 `read_bytes()`，文件不在就抛异常、连接被断开。已补上，现在冻结版与源码版
行为一致。

`serve --pipe --no-http` 连端口都不开，只推 Windows 命名管道（协议见主 README
「命名管道」一节）：

| 端点 | 用途 |
|---|---|
| `GET /api/state` | ok-end-field 唯一的必需接口（轮询或给 SSE 缓存） |
| `GET /api/travel-poles` | 本次登录同步的滑索节点、坐标、朝向与默认下一站 |
| `GET /api/events` | SSE 推送，想改成"推"而不是"拉"时用 |
| `GET /api/scene-index` | 场景号 → 关卡/中文名/副本/大地图（读包内预存表） |
| `GET /api/positions.csv` | 本次会话的坐标 CSV |

前提是没有加 `--no-dashboard`；加了 `--no-http` 就只有管道这一个出口。

## 怎么被 ok-end-field 调用

ok-end-field 侧**不需要**任何抓包依赖：它只读 `GET /api/state`，并且会在后端没在跑时
自动把本 exe 拉起来（可关）。完整约定、启动顺序与坐标陈旧度的处理见
[../docs/ok-end-field-integration.md](../docs/ok-end-field-integration.md)。
