# endfield-capture-backend

被动抓取《明日方舟：终末地》游戏主 TCP 连接，**离线**解出当前操控角色的世界坐标，并通过本地
HTTP 看板暴露出来。

用一个 [ok-end-field](https://github.com/AliceJump/ok-end-field) 之类的自动化程序时，绝对坐标通常
来自「小地图里程计 + 官方地图 WS 融合」——那条链要维护分辨率相关的比例尺标定、静止校准和漂移校正。
本项目提供另一条路：**游戏自己在网络上报的坐标**。它与官方地图 WS 的坐标逐位一致，落在同一世界
坐标系里，并且额外自带真实的**高度**与**朝向**。

> [!WARNING]
> **该技术可能违反游戏服务条款，存在账号被异常处置的风险。**
>
> 本项目通过读取网卡上的流量副本、并用客户端自身内嵌的材料解开该流量来工作。请在使用前自行
> 判断这在你的情形下是否可接受。作者不对任何后果负责。
>
> 本项目**不**注入进程、**不** Hook 游戏、**不**读取游戏进程内存、**不**修改任何游戏文件，
> 只读网卡上的被动副本与调用方本机已有的客户端文件。

## 它是什么，不是什么

| 是 | 不是 |
|---|---|
| 对本机游戏流量的被动监听 | 抓包分析工具（不导出密钥，不提供通用解密） |
| 与官方地图坐标同坐标系的位置来源 | 内存读取器或注入器 |
| 一个本地看板 + 一个可被别的程序读取的 HTTP 接口 | 游戏服务器行为的权威解释 |

**服务端是否接受客户端上报的每一次位置、是否另有权威校正，本项目没有验证。** 这里给出的是
「客户端在网络上说了什么」，不是「服务器最终裁定你在哪」。

## 工作原理

### 已验证客户端

当前支持国服和 GRYPHLINK 国际服的两份已验证构建，完整 DLL / metadata 指纹与材料定位定义在
`src/endfield_capture/client_profiles.py`。未知构建仍会拒绝启动，不能通过删除版本校验来适配。
两服分别使用绑定各自指纹的公钥模数文件；国际服模数已通过其真实新连接握手、原生离线模拟
以及后续连续业务帧回放验证。国际服样本处于首次角色身份选择阶段，尚未验证完整世界中的长期运行。

请用 `--game-dir` 或 `EF_GAME_DIR` 明确选择客户端；同时安装两服时，默认目录可能优先找到国服。
例如：`endfield-capture-backend serve --game-dir "F:/Arknights Endfield" --no-map-ws`。
国际服沿用同一套 TCP 重组、ChaCha20、protobuf 与坐标消息解析，仍须在新游戏连接建立前开启监听。
SDK 初始化日志或标题页出现不代表已经捕获游戏主连接握手。

SRSA 模拟回退已重新核对当前版本的原生跳板与模幂观测地址；生成工具按实际选中的客户端
写入对应公钥文件，不会把国际服结果标成国服。原始抓包、私钥与会话参数不进入版本库。
本地验证原生回退可设置 `EF_NATIVE_REFERENCE_PCAP` 与 `EF_GAME_DIR`，再运行
`uv run --locked python -m unittest discover -s tests -p test_client_profiles.py`。

一条坐标要穿过这些层，全部由本仓库实现，全部离线：

```
TCP 重组（含乱序 / 重传 / 重叠）
  → [1B 头长][2B 小端体长][消息头][消息体]      ← 长度前缀是明文
  → 首帧：SRSA 原生封装 ── 模拟客户端原生接收路径 ──→ 明文 MSG_B1
  → MSG_B1.F3 用客户端内嵌 RSA 私钥解包 → 32 字节会话 key；F4 → 12 字节 nonce
  → XXE1（= 标准 ChaCha20）连续流
      消息头字段 6 = 是否 LZ4
      消息头字段 4/5 = 分片总数 / 序号
      消息 81 = CS_MOVE_OBJECT_MOVE（含坐标）；消息 500 = 合并包，里面可能再套 81
  → move_info[i].motion_info.position.{x,y,z}，i == leader_index 的那条是当前操控角色
```

三个不显然但决定成败的点：

1. **长度前缀不参与加密**，所以能逐帧定位；但**消息头和消息体参与**。
2. **加密不是从连接第一个字节开始的**：上行第一个明文帧（消息号 13）体上还套了一层原生封装，
   且发生在流加密启用之前。按 TCP 包重置 ChaCha20 状态、或把明文序言的范围猜错，都会让
   整个方向**从错误的流位置**推进，之后全错。
3. **抓包必须早于该连接建立**。会话初始化只在连接开头出现一次；中途开始抓包拿不到它。
   遇到这种情况本项目会明确报「缺少连接起点」，而不是解出看似合理实则错位的数据。

关于原生那层的细节：`Beyond.SRSA.LoadFromFile2` 的入口在受保护代码里，线性反汇编还原不出执行
顺序，所以本项目把 DLL 指令、常量页、栈与输入缓冲区放进一个 x86-64 模拟器按需映射 PE 页跑一遍
（只实现 `HeapAlloc`/`HeapFree` 两个系统导入）。跑通之后能确认：被处理的大整数就是封装体第 16
字节之后的 256 字节按大端解释，指数恒为 65537，于是可用 `pow(c, 65537, n)` 在纯 Python 里复现，
此后不再需要模拟器。

## 依赖

- **Python 3.12**
- **Npcap**（Windows 抓包驱动，需勾选 "WinPcap API-compatible Mode"）— [下载](https://npcap.com/)
- 本机安装的《终末地》客户端（用于读取 `GameAssembly.dll` 与 `global-metadata.dat`）
- 可选：官方地图 WS 对照需要一份 [ok-end-field](https://github.com/AliceJump/ok-end-field) 仓库
  与其中的账号配置。用 `uv sync --extra ws-compare` 安装额外依赖（含 ok-script）。
  不装也能正常用，只是没有对照。

客户端文件**不随本项目分发**，必须是你自己机器上已安装的那份。

## 安装

```bash
uv sync
# 或者
pip install -e .
```

### 不装 Python 的机器：打成单个 exe

```bash
uv run --with pyinstaller pyinstaller packaging/endfield-capture-backend.spec --noconfirm
```

产物 `dist/endfield-capture-backend.exe`（onefile，19.2 MB），用法与命令行版一致。
场景表与公钥模数两份数据已经打进包里，目标机器上不需要 Python，也不需要额外的数据文件
（但**仍然需要 Npcap 驱动与本机客户端**）。细节、体积构成与「为什么冻结版不带 unicorn」
见 [packaging/README.md](packaging/README.md)。

## 用法

### 启动看板

**先启动本程序，再启动游戏。** 顺序反了就抓不到登录握手。

```bash
uv run endfield-capture-backend serve --port 8765
```

浏览器打开 <http://127.0.0.1:8765/>。

常用参数：

| 参数 | 说明 |
|---|---|
| `--game-dir` | 客户端安装目录；默认按常见位置探测，也可用环境变量 `EF_GAME_DIR` |
| `--interface` | 抓包网卡（网卡名或 IP）；留空按默认路由自动选 |
| `--seed-pcap` | 先开新抓包，再重放一份旧捕获，用来**接管一个已经在跑的游戏会话** |
| `--runs-dir` | 运行产物目录，默认 `./runs` |
| `--no-map-ws` | 不启用官方地图 WS 对照 |
| `--no-dashboard` | 不提供网页看板，只留 `/api/*`（给 ok-end-field 或后台运行时选这个） |
| `--pipe [名字]` | 额外把坐标推到 Windows 命名管道（不带名字时用 `\\.\pipe\endfield-capture-positions`） |
| `--no-http` | 连 HTTP 也不起，只用命名管道（需配合 `--pipe`；这样**不占任何端口**） |
| `--ok-end-field` | ok-end-field 仓库路径（仅为启用 WS 对照，默认自动探测同级目录） |
| `--account` / `--content` | 地图 WS 用哪个账号的 content；配置里有多份时必须指定 |

> 启用 WS 对照会让本项目与 AGPL-3.0 的 ok-end-field 链接在一起；不启用则完全不依赖它。

### 游戏已经在跑怎么办

看板会显示 `缺少连接起点，请重新启动游戏`。两条出路：

1. **重开游戏**，或
2. 用 `--seed-pcap` 指向一份**从登录前开始**的完整抓包（比如上一次运行留在 `runs/` 里的
   `capture.pcap`）。程序会先开新抓包，再重放旧捕获把状态接上，重放样本标为 `replayed`
   且不计入在线延迟统计。

### 自检

改完代码、或客户端更新后，先跑自检：

```bash
uv run endfield-capture-backend selftest path/to/full-session.pcap
```

它会回放整份抓包，核对移动消息 / 对象位置 / 主控位置的数量与最后一条坐标，并且额外
**打乱顺序 + 注入重复包**再跑一遍以验证 TCP 重组。任何一项不符即以非零码退出。

预期数值在 `src/endfield_capture/selftest.py` 的 `REFERENCE_EXPECTATION`，它描述的是研究阶段
那次**参考会话**（137 移动 / 229 对象 / 39 主控）。核对别的抓包会用 `--expect` 传自己的预期值。

> **参考会话那份抓包不进仓库。** 它是一次真实会话的完整流量，含登录握手、两端 IP 与精确时间，
> 放进公开历史就撤不回来。想跑这条回归就本地放一份完整会话（**必须含登录握手**）到
> `tests/data/reference-session.pcap`（已在 `.gitignore` 里），或用 `EF_REFERENCE_PCAP` 指到别处
> ——`tests/test_selftest_reference.py` 会用它，没有就跳过。自己抓一份的办法见
> [「游戏已经在跑怎么办」](#游戏已经在跑怎么办)：先起后端再开游戏，`runs/<时间戳>/capture.pcap`
> 就是完整会话。

## 看板与 HTTP 接口

`GET /api/facilities` 可读取本次登录同步的全部工厂设施：节点、坐标/朝向、类型化组件 payload、
端口和地图线路。覆盖电力、生产、仓储、传送带、管道等，不按滑索模板过滤；
`/api/state.facilities` 仅提供轻量摘要。字段、同步范围和使用方式见 [工厂设施快照](docs/facilities.md)。

除角色坐标外，`GET /api/travel-poles` 可读取本次登录同步的工厂滑索节点、坐标与建筑朝向、
类型、共享/供电字段及有向默认下一站。支持 221 完整同步、222 节点增删改和 223 组件更新；
重登录会清空旧会话数据。`/api/state.travelPoles` 只提供摘要，完整数据按需查询。
启动顺序、字段语义、缺失目标处理及验证范围见 [滑索接口说明](docs/travel-poles.md)。

看板显示主控角色的世界坐标、轨迹、消息流水、连接状态，以及（可选）与官方地图 WS 的对照。

程序化读取用 `GET /api/state`，其中：

- `lastPosition` — 最新一条坐标：`x` / `y` / `z` / `yaw`（度，正北 0、顺时针）/ `speed`
  （世界单位/秒）/ `scene`（`sceneNumId`）/ `levelId` / `levelName` / `dungeonName` /
  `mapId` / `mapName` / `time`（抓包时间戳）
- `sceneMaps` — **`sceneNumId` 与本会话观测到的地图名的共现统计**，外加本地场景表查出来的
  `declared`（`levelId` / `levelName` / `source` / `dungeonId` / `dungeonName` / `seriesName` /
  `category` / `dungeonCount` / `mapId` / `mapName` / `domain`），用来人工核对场景与导航网格的对应关系
- `flows` — 每条连接的解码状态；出现「缺少连接起点」说明抓包启动太晚

> **关于地图名**：`sceneNumId` **不是**地图的一一对应键——实测同一个地图可以有多个场景号。
> 权威来源是游戏地图服务自己下发的 `mapId`（看板通过官方 WS 对照取得）。`sceneMaps`
> 就是给你核对这两者关系用的。

坐标写盘（`positions.jsonl`）、CSV 导出与 SSE 里都会带上 `levelId` / `levelName` /
`dungeonName` / `mapId` / `mapName`，直接由场景号查出来，不需要 WS 对照。整张表用
`GET /api/scene-index` 取：

```json
{
  "count": 221,
  "maps": {"base01": "帝江号", "map01": "四号谷地", "map02": "武陵"},
  "scenes": [
    {"scene": 232, "levelId": "map02_lv005", "levelName": "试验园区", "dungeonId": "",
     "dungeonName": "", "seriesName": "", "category": "", "dungeonCount": 0,
     "mapId": "map02", "mapName": "武陵", "domain": "domain_2"},
    {"scene": 310, "levelId": "dung01_cdg011", "levelName": "物以类聚",
     "dungeonId": "dung01_actmonster01", "dungeonName": "物以类聚", "seriesName": "生存特训",
     "category": "dungeon_actmonster", "dungeonCount": 1,
     "mapId": "map01", "mapName": "四号谷地", "domain": "domain_1"}
  ]
}
```

### 命名管道（可选传输）

不想让消费方轮询 HTTP，就让它读 Windows 命名管道 —— Qt 的 `QLocalSocket` 直接读，不占端口：

```powershell
endfield-capture-backend serve --pipe --no-http        # 只推管道，不开任何端口
endfield-capture-backend serve --pipe \\.\pipe\my-ef   # 换名字
```

协议极简：**换行分隔的 UTF-8 JSON，每行一个对象，带 `type` 字段**。

```
{"type": "hello", "protocol": 1, "pid": 1234, "pipe": "\\\\.\\pipe\\endfield-capture-positions", "runDirectory": "runs/..."}
{"type": "position", "time": 1791870088.9, "scene": 361, "levelId": "map02_lv009", "levelName": "雪松林",
 "dungeonName": "", "mapId": "map02", "mapName": "武陵", "x": 172.04, "y": 105.25, "z": 47.89,
 "yaw": 308.8, "speed": 5.75, "state": 3, "merged": false}
```

`position` 行的字段与 `GET /api/state` 的 `lastPosition` 完全一致，消费方换传输不用改解析。

- 连上先给 `hello`，紧接着补一条**当前最新坐标**（有的话），然后才是实时流；
- **没有客户端时不排队**：只留最新一条，重连不会收到一堆积压的旧位置；
- 写不过来时丢新样本（`/api/state` 的 `pipe.dropped` 能看到），**不阻塞解码**；
- 不碰端口、不弹防火墙；管道是文件对象，跟读内存无关（有守卫测试钉着这条底线）。

Python 侧调试一行就够（管道就是文件）：

```powershell
python -c "import json;[print(json.loads(l)['type'], json.loads(l).get('scene')) for l in open(r'\\.\pipe\endfield-capture-positions', encoding='utf-8')]"
```

### 场景表

`src/endfield_capture/scene_index.py` 里的 `SCENE_INDEX` 是
`sceneNumId` → 关卡 → 中文名 → 副本/系列 → 大地图 的查表。四层逐层都可能有缺，缺就留空，不猜。
`sceneNumId` 就是客户端 `LevelBasicInfoTable` 的 `idNum`（用抓包核对过：102 / 228 / 232
分别落在 `map02_lv007` / `map02_lv002` / `map02_lv005`，坐标也都落在 map02 主网格范围内）。
关卡名来自 `LevelDescTable` 经客户端文本表解出（没有就退回副本名）；副本来自
`DungeonTable` 里 `sceneId` 指向该关卡的条目——注意不是 `levelId`，那是副本加载用的底图
（靶场那批全都写着 `map02_lv009`）。一个场景被多个副本共用时取 `dungeonId` 排序最前的那个，
共用数量记在 `dungeonCount`（例如 `dung01_ttdg001` 是 16）。
地图归属按这个优先级判：`SpecialLevelToMapTable` 的显式声明 → 关卡 id 前缀
（`map01` / `map02` / `base01`）→ 地下城前缀（`dung01` → map01、`dung02` → map02）→
没有所属大地图（`blackbox_*`、多数 `indie_*`）。`domainName` 只作参考字段带出，**不参与判定**：
实测同一个前缀会横跨 `domain_1` / `domain_2`。

**运行时只读这张表**：`scene_index.py` 打开包内的 `data/scene_index.json` 建查表，自己不解包、
不推导、不生成任何东西；**读不到表就拒绝启动**（那和「这个号查不到」是两回事）。想用别的
快照，把它指到另一份 JSON 即可：

```powershell
$env:EF_SCENE_INDEX = "D:\somewhere\scene_index.json"
```

表本身是客户端版本的快照，由离线工具生成一次（需要解包产物）：

```bash
# 用环境变量指出输入表的两个根（仓库里不留本机路径）
setx EF_MAP_EXPORT_DIR "D:\somewhere\Endfield_Map_Export"    # 含 Json/ 与 Readable/TableCfg_json/
setx EF_TABLE_JSON_DIR "D:\somewhere\TableCfg_json"          # 解包工具解出的名字类表

python tools/generate_scene_index.py              # 写 src/endfield_capture/data/scene_index.json
python tools/generate_scene_index.py --dry-run    # 只看统计
python tools/generate_scene_index.py --out <路径>  # 打到别处（配合 EF_SCENE_INDEX）
# 单个表也能单独覆盖：--levels / --special / --desc / --i18n / --text / --dungeons / --series
```

两个环境变量都没设时，按当前工作目录下的 `./Endfield_Map_Export` 与 `./TableCfg_json` 找。

> **导出必须包含 `Persistent/VFS` 那一层。** 客户端有 `Endfield_Data/StreamingAssets/VFS` 与
> `Endfield_Data/Persistent/VFS` 两个 VFS 根，**后者优先级更高**，同一路径的文件以后者为准。
> 只读 StreamingAssets 的导出会漏内容——实测 `Json/` 组有 400 个文件只存在于 Persistent，
> 其中 `Json/GameplayConfig/LevelBasicInfoTable.json` 在那边有 **221** 条关卡、在
> StreamingAssets 里只有 **216** 条。拿后者生成，表就少 5 个场景（`463` 遂明、
> `525` 兽影生杀、`526` 沛然轰鸣、`527` 暗曜白霆、`550` 三角定位），查这些场景号会全空。
> 生成时打印的场景数就是这条的体检指标：本机这份客户端应为 **221**。
> `tests/test_scene_index.py` 里`test_persistent_vfs_levels_are_present` 直接钉住那 5 个场景，
> 数字掉回去就会被测出来。

另有一份同类预存数据 `data/rsa_modulus.json`：恢复登录响应要用的 2048 位公钥模数。它同样
由离线工具生成一次，运行时**优先读它**、读不到才回退到 x86 模拟器——
打包出来的 exe 走的正是前者（冻结进程里 unicorn 的 JIT 会崩）。客户端更新后要重跑：

```bash
python tools/generate_rsa_modulus.py             # 自动取 runs/ 里最新的一份抓包
python tools/generate_rsa_modulus.py --pcap <路径>
```

细节见 [packaging/README.md](packaging/README.md)。

#### 查不到的场景号：别把它们当成场景号

这张表只有 `LevelBasicInfoTable.idNum` **一个编号空间**，查不到就返回 `null`，不做推测。
客户端里同时存在好几套编号，**数字会撞车**，所以查不到时先分清是哪种：

- **「没有 idNum 的关卡」其实不存在**：一个**完整**的解包产物里，`LevelBasicInfoTable`
  （221 条）与 `Json/LevelConfig/` 下的关卡文件**是同一个集合**，没有多出来的关卡 id。
  这条曾经写的是「216 个关卡之外还有 22 个关卡 id」，并点名 `indie_dg016` 遂明、
  `indie_hdg026` 兽影生杀等 5 个「没有场景号」——那是**导出只读了 `StreamingAssets/VFS`**
  造成的假象：这几个关卡在 `Persistent/VFS` 里，而它们的场景号一直存在
  （463 / 525 / 526 / 527 / 550），现在已在表里。详见上面「导出必须包含 Persistent/VFS」。
  `LevelGaps_resolved.json` 与文本表里另有 `blackbox_filling_5` / `blackbox_power_1` 这类
  名字，但它们在关卡表与 LevelConfig 里都查不到——是被声明而未实现的关卡，不是场景号。
- **`MapConfig.mapId` 是另一个空间**：解包产物 `Data/Json/MapConfig/*.json` 里每条地图配置都带
  一个 `mapId`（例如 `dung02_gdg013` 的 `mapId` 就是 **463**，它的 `levelIds` 全是 468）。
  这套号跟本表的场景号**会撞车**——最典型的是 `2`：既是 `map01` 的地图号，又是
  `map01_lv002` 的场景号。所以**不能**拿 `mapId` 当场景号查，反之亦然。
- `LevelShortIdTable` 里的短 id（如 `463` → 长 id `23100031243`，属于 `map02_lv008`）又是
  第三套，同样不能混用。**注意 `463` 正好两套都占**：作为短 id 它指 `map02_lv008`，作为本表的
  场景号它指 `indie_dg016`（遂明）——这就是为什么查号前必须先确定手里是哪种编号。

## 与 ok-end-field 协作

[ok-end-field](https://github.com/AliceJump/ok-end-field) 侧的接入已经就位，不需要任何抓包
依赖：它只读 `GET /api/state`，并且会在后端没在跑时**自动把 exe 拉起来**。

一句话说清调用关系：

```
ok-end-field 定位任务 ──拉起(可选)──> endfield-capture-backend.exe serve --no-dashboard --no-map-ws
        ▲                                              │
        └────────── 轮询 GET /api/state ───────────────┘
```

**顺序是成败关键**：后端必须早于游戏的主连接就绪，否则拿不到登录握手。让应用拉起后端就能
保证这个顺序（先在 ok-end-field 里勾上「使用实验技术」，再启动游戏）。

**游戏内退出登录、重新登录（含切换账号）会自动接管**：每次登录都是一条**新的 TCP 连接**、
一次**全新的握手**（会话密钥由服务端按账号下发，每个账号不同），后端发现新连接后就接着解码，
不需要重启后端。反过来，**后端重启救不了任何解码问题**——最近一次握手的密钥只在登录那一刻
出现过一次，重启就等于把它丢了，当前这一局只能重开游戏。判断"接没接上"看 `GET /api/state`
的 `flows[].status` 是不是 `正在解码`，**别看 `lastPosition`**（它一旦有值就永远保留，重登录
前后长得一模一样）。细节见 [docs/ok-end-field-integration.md](docs/ok-end-field-integration.md)
的「连接生命周期」一节。

应用侧相关配置：端口（默认 8765）、后端程序路径（留空自动探测）、是否自动启动、
是否在停止定位时关闭后端（**默认不停**——后端状态绑在当前这一局连接上，关掉再拉起就等于
丢了登录握手）。

完整契约、字段表、坐标陈旧度语义、地图名判定顺序与故障排查表见
[docs/ok-end-field-integration.md](docs/ok-end-field-integration.md)。

## 项目边界与已知限制

- **客户端版本强绑定**：脚本按已核对的客户端哈希写死了函数 RVA 与静态材料位置。哈希不符时
  程序**拒绝启动**并打印实际哈希，而不是继续解出错的数据。客户端每次更新都需要重新核对。
- **只验证过一个场景与一张地图**（一个地点、约 8 秒行走）。战斗、传送、切图、载具等情形
  尚未系统验证。
- **服务器权威性未验证**（见上）。
- **上报是事件驱动的，不是周期性的**：移动中约每 0.27 秒一条；**完全静止时没有位置包**。
  同图传送会造成数秒到数十秒的空档。**本项目不做任何陈旧度策略**——不丢弃旧坐标，也没有
  超时参数：`lastPosition` 一旦有值就一直保留（哪怕那一局游戏已经结束），消费方必须自己拿
  `lastPosition.time`（抓包时刻的 Unix 墙钟）减去当前墙钟来判定还能不能用。这个减法**两边
  都得是墙钟**：用单调钟去减 Unix 时间戳会恒为负、被夹成 0，让安全提示彻底失效。
- **Npcap 需要管理员权限安装**；部分网卡/驱动组合下抓包可能丢包。

## 开发

```bash
uv run ruff check .
uv run python -m unittest discover -s tests
uv run endfield-capture-backend selftest <pcap>
```

模块划分（大致按一条坐标流经的顺序：入口 → 解码链 → 两个出口 → 验证）：

| 模块 | 职责 |
|---|---|
| `cli.py` | 命令行入口：`serve` / `selftest` |
| `pe_image.py` | 最小 PE 解析（节表、VA↔文件偏移），只读本地文件 |
| `srsa.py` | 离线模拟原生接收入口，恢复公钥模数 |
| `schema.py` | 用独立 protobuf 描述复核解出的坐标 |
| `decoder.py` | TCP 重组、分层解密、消息与坐标解析 |
| `scene_index.py` | 只读查表：场景号（`idNum`）→ 关卡 → 中文名 → 副本/系列 → 大地图（读 `data/scene_index.json`） |
| `map_compare.py` | 可选的官方地图 WS 对照（需 ok-end-field，启用即与 AGPL-3.0 链接） |
| `server.py` | 抓包 + 本地 HTTP 看板 |
| `pipe_server.py` | 命名管道推送（`--pipe`），给同机消费方读 |
| `selftest.py` | 回放核对 |

包内另有两个资源目录，代码平铺在包根：

| 目录 | 内容 |
|---|---|
| `data/` | 两份**离线生成**的运行时数据：`scene_index.json`（场景表）、`rsa_modulus.json`（公钥模数）。运行时只读，生成脚本在 `tools/` |
| `static/` | 看板页面 `dashboard.html`（`--no-dashboard` 时不读） |

## 许可

AGPL-3.0-or-later，见 [LICENSE](LICENSE)。
