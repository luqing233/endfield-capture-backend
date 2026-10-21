"""被动抓包 + 增量解码：把游戏主 TCP 连接里的角色坐标解出来。

## 能解的前提

登录响应发出之前那一帧里带着会话所需的一切，而且**只在连接建立时出现一次**。所以：

- 抓包必须**早于**该 TCP 连接建立，否则拿不到会话起点（见 :class:`Flow` 的状态提示）；
- 上行与下行各自维护一份独立的连续流状态，重连必须重新初始化。

## 一条坐标要穿过哪些层

```
TCP 重组 → [1B 头长][2B 小端体长][消息头][消息体]
  首帧：SRSA 原生封装 → 明文 MSG_B1
         MSG_B1.F3 = RSA 包装的 32 字节会话 key，F4 = 12 字节 nonce
  之后：XXE1(=标准 ChaCha20) 连续流 → 消息头字段 6 = 是否 LZ4、字段 4/5 = 分片
        消息 81 直接给坐标；消息 500 是合并包，里面可能再套 81
```

## 关于密钥

会话 key 由**服务端**下发，用客户端内嵌的 RSA 私钥解开；公钥模数由离线模拟客户端原生
接收路径恢复。这两样都留在内存里，不落盘、不出日志、不提供给页面。

## 不做的事

不注入、不 Hook、不改游戏内存、不碰游戏文件。只读网卡上的被动副本与调用方给出的本地
客户端文件。
"""

from __future__ import annotations

import base64
import gc
import hashlib
import json
import struct
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from Crypto.Cipher import ChaCha20
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from lz4.block import decompress as lz4_decompress

from .client_profiles import CN_PROFILE, modulus_data_path, profile_for_digest
from .facilities import FacilityStore
from .pe_image import PeImage
from .scene_index import resolve_scene
from .schema import PositionMessage
from .travel_poles import TravelPoleStore

__all__ = [
    "CLIENT_DLL_SHA256",
    "CLIENT_METADATA_SHA256",
    "METADATA_RELATIVE_PATH",
    "Bootstrap",
    "Engine",
    "Flow",
    "PositionRecord",
    "Reassembler",
    "State",
    "protobuf_fields",
]

#: 已核对过的客户端哈希。对不上就拒绝启动——函数 RVA 和静态材料会随版本改变，
#: 继续跑只会安静地解出错的东西。
CLIENT_DLL_SHA256 = CN_PROFILE.dll_sha256
CLIENT_METADATA_SHA256 = CN_PROFILE.metadata_sha256

METADATA_RELATIVE_PATH = "Endfield_Data/il2cpp_data/Metadata/global-metadata.dat"

#: 预存的公钥模数（由 ``tools/generate_rsa_modulus.py`` 离线生成）；不在就打不动模拟器
MODULUS_DATA_PATH = modulus_data_path(CN_PROFILE)

#: 会话流从 ChaCha20 密钥流的第 64 字节开始（前 64 字节已被初始化消耗）
_CIPHER_SEEK_BYTES = 64

#: 单个方向上等待初始化的累积缓冲上限，防止中途接管时无限增长
_BUFFER_LIMIT = 32 * 1024 * 1024

#: 乱序缓存上限
_REORDER_LIMIT = 32 * 1024 * 1024


def protobuf_fields(raw: bytes) -> dict[int, list[Any]]:
    """最小的 protobuf 线格式解析：`{字段号: [值, ...]}`。

    只按需求解，不需要 `.proto` 描述；重复字段天然成为列表。
    """

    fields: dict[int, list[Any]] = defaultdict(list)
    at = 0

    def read_varint() -> int:
        nonlocal at
        result = 0
        for shift in range(0, 70, 7):
            if at >= len(raw):
                raise ValueError("varint 被截断")
            byte = raw[at]
            at += 1
            result |= (byte & 127) << shift
            if byte < 128:
                return result
        raise ValueError("varint 过大")

    while at < len(raw):
        tag = read_varint()
        number, wire = tag >> 3, tag & 7
        if number < 1:
            raise ValueError("字段号无效")
        if wire == 0:
            value: Any = read_varint()
        else:
            length = read_varint() if wire == 2 else 8 if wire == 1 else 4 if wire == 5 else -1
            if length < 0 or at + length > len(raw):
                raise ValueError("长度前缀无效")
            value = raw[at : at + length]
            at += length
        fields[number].append(value)
    return dict(fields)


def value(fields: dict[int, list[Any]], number: int, default: Any = 0) -> Any:
    """取字段的最后一个值（protobuf 的"后者覆盖前者"语义）。"""

    rows = fields.get(number)
    return rows[-1] if rows else default


def tcp_payload(packet) -> bytes:
    """取 TCP 负载，并按 IP 总长截断，去掉以太网最小帧的补齐字节。

    ``ip.len`` 在真实抓包里总是有值；构造出来的包可能没填，这时按负载原样处理，
    免得一个缺失字段就让整条流转入失败。
    """

    payload = bytes(packet[TCP_LAYER].payload)
    total = packet[IP_LAYER].len
    if total is None:
        return payload
    header = int(packet[IP_LAYER].ihl) * 4 + int(packet[TCP_LAYER].dataofs) * 4
    return payload[: max(0, int(total) - header)]


# scapy 层在导入时绑定，方便本模块在没有 scapy 的环境下也能被静态检查
try:  # pragma: no cover - 导入期副作用
    from scapy.all import IP as IP_LAYER
    from scapy.all import TCP as TCP_LAYER
except ImportError:  # pragma: no cover
    IP_LAYER = TCP_LAYER = None  # type: ignore[assignment]


@dataclass
class PositionRecord:
    """一条解出的角色坐标。"""

    time: float
    flow: int
    object_id: str
    scene: int
    x: float
    y: float
    z: float
    heading: float | None
    speed: float | None
    state: int
    merged: bool
    #: 场景号经 :mod:`endfield_capture.scene_index` 查出来的关卡、副本与地图；表里没有时为空
    level_id: str = ""
    level_name: str = ""
    dungeon_name: str = ""
    map_id: str = ""
    map_name: str = ""
    sample_id: int = 0
    capture_at: float | None = None
    callback_at: float | None = None
    processing_started_at: float | None = None
    decoded_at: float | None = None
    decode_ms: float | None = None
    queue_ms: float | None = None
    capture_to_decoded_ms: float | None = None
    replayed: bool = False
    game_server_time: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "time": self.time,
            "flow": self.flow,
            "objectId": self.object_id,
            "scene": self.scene,
            "levelId": self.level_id,
            "levelName": self.level_name,
            "dungeonName": self.dungeon_name,
            "mapId": self.map_id,
            "mapName": self.map_name,
            "x": self.x,
            "y": self.y,
            "z": self.z,
            "yaw": self.heading,
            "speed": self.speed,
            "state": self.state,
            "merged": self.merged,
            "sampleId": self.sample_id,
            "captureAt": self.capture_at,
            "callbackAt": self.callback_at,
            "processingStartedAt": self.processing_started_at,
            "decodedAt": self.decoded_at,
            "decodeMs": self.decode_ms,
            "queueMs": self.queue_ms,
            "captureToDecodedMs": self.capture_to_decoded_ms,
            "replayed": self.replayed,
            "gameServerTime": self.game_server_time,
        }


class Bootstrap:
    """每局连接初始化一次的材料：公钥模数 + 客户端内嵌 RSA 私钥。

    公钥模数按两条路拿：

    1. **预存的数据**（``data/rsa_modulus.json``，由 ``tools/generate_rsa_modulus.py`` 离线
       生成一次）——客户端哈希对得上就直接用，**完全不碰模拟器**。打包出来的二进制走这条。
    2. 数据缺失或与客户端对不上时，回退到**离线模拟器**：拿第一条登录响应当样本，把客户端
       DLL 的机器码在 unicorn 里跑一遍恢复模数。这条路只在装了 unicorn 的源码环境里可用。

    两条路都要先核对客户端哈希；完成后立刻丢掉整份 DLL 镜像——之后全是纯 Python 运算。
    """

    def __init__(self, game_directory: Path):
        started = time.perf_counter()
        self.game_directory = Path(game_directory)
        image = self._load_verified_image()
        self._private = self._load_client_private_key(image)
        self._image: PeImage | None = image
        #: ``"data"`` = 用的是预存模数；``"emulated"`` = 现场模拟恢复的；``None`` = 还没有
        self.modulus_source: str | None = None
        self._modulus: int | None = self._load_stored_modulus()
        if self._modulus is not None:
            self.modulus_source = "data"
        self.modulus_seconds: float | None = None
        self.key_seconds = time.perf_counter() - started

    @property
    def modulus(self) -> int | None:
        """当前用的公钥模数；``None`` 表示还没恢复。"""

        return self._modulus

    # ------------------------------------------------------------------ #
    # 客户端材料
    # ------------------------------------------------------------------ #
    def _load_verified_image(self) -> PeImage:
        path = self.game_directory / "GameAssembly.dll"
        if not path.is_file():
            raise ValueError(f"找不到客户端文件 {path}")
        image = PeImage(path)
        digest = hashlib.sha256(image.buf).hexdigest()
        self.profile = profile_for_digest(digest)
        self.modulus_data_path = modulus_data_path(self.profile)
        return image

    def _load_client_private_key(self, image: PeImage):
        """从 metadata 的字符串字面量表里读客户端内嵌的 RSA 私钥（base64 DER）。"""

        metadata = self.game_directory / METADATA_RELATIVE_PATH
        if not metadata.is_file():
            raise ValueError(f"找不到客户端元数据 {metadata}")
        with metadata.open("rb") as file:
            digest = hashlib.file_digest(file, "sha256").hexdigest()
            if digest != self.profile.metadata_sha256:
                raise ValueError(
                    f"客户端元数据版本已改变（global-metadata.dat sha256={digest}）"
                )
            slot = image.image_base + self.profile.key_literal_rva
            word = image.u64_at_va(slot)
            # IL2CPP usage slot: string-literal kind 5 plus its encoded index.
            if not (word & 1 and word >> 29 == 5):
                raise ValueError("RSA 初始化字段的编码与预期不符")
            index = (word >> 1) & 0xFFFFFFF
            file.seek(8)
            literal_table, _, literal_data, _ = struct.unpack("<IIII", file.read(16))
            file.seek(literal_table + 8 * index)
            length, offset = struct.unpack("<ii", file.read(8))
            file.seek(literal_data + offset)
            material = file.read(length)
        return serialization.load_der_private_key(base64.b64decode(material), password=None)

    # ------------------------------------------------------------------ #
    # 公钥模数
    # ------------------------------------------------------------------ #
    def _load_stored_modulus(self) -> int | None:
        """读预存的模数；哈希对不上就当没有（不报错，回退模拟器）。"""

        if not self.modulus_data_path.is_file():
            return None
        try:
            payload = json.loads(self.modulus_data_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        same_client = (
            payload.get("client_dll_sha256") == self.profile.dll_sha256
            and payload.get("client_metadata_sha256") == self.profile.metadata_sha256
        )
        modulus = payload.get("modulus_hex") or ""
        if not same_client or not modulus:
            return None
        try:
            value = int(modulus, 16)
        except ValueError:
            return None
        return value if value.bit_length() >= 1024 else None

    def _recover_modulus(self, envelope: bytes) -> int:
        """用一条真实的登录响应跑一遍原生模拟，恢复公钥模数。"""

        image = self._image
        if image is None:
            # 已经释放过镜像说明模数早就恢复了，不该走到这里
            raise RuntimeError("公钥模数恢复失败：客户端镜像已释放")
        try:
            from .srsa import emulate_receive_entry
        except ImportError as exc:  # 打包版故意不带 unicorn / capstone
            raise RuntimeError(
                f"这条客户端没有可用的预存模数，而本程序不含模拟器（{exc}）。"
                f"请用 tools/generate_rsa_modulus.py 生成 {self.modulus_data_path}，"
                "或用装了依赖的源码环境运行。"
            ) from exc
        started = time.perf_counter()
        result = emulate_receive_entry(image, envelope)
        if not result.ok or result.modulus is None:
            reason = (result.state or {}).get("stop") or (result.state or {}).get("error")
            raise ValueError(f"原生接收路径模拟未跑通：{reason}")
        self._modulus = result.modulus
        self.modulus_source = "emulated"
        self.modulus_seconds = time.perf_counter() - started

        # 自证：纯 Python 的 pow 结果必须与模拟输出逐字节相同，否则不采用这个模数。
        if self._pow_unwrap(envelope) != result.transformed:
            self._modulus = None
            raise ValueError("恢复出的模数与模拟输出不一致，拒绝使用")
        del result
        # 模数到手后 DLL 就没用了：丢掉整份镜像，避免常驻上百 MB
        self._image = None
        gc.collect()
        return self._modulus

    def _pow_unwrap(self, envelope: bytes) -> bytes:
        """等价的纯 Python 还原：大端读入 → 模幂 → 小端写出 → 按原始长度截断。"""

        if self._modulus is None:
            raise RuntimeError("公钥模数尚未恢复")
        length = int.from_bytes(envelope[8:12], "little")
        if not 0 < length <= 256:
            raise ValueError(f"登录封装声明的明文长度异常: {length}")
        recovered = pow(int.from_bytes(envelope[16:], "big"), 65537, self._modulus).to_bytes(256, "little")
        return recovered[:length]

    def unwrap(self, envelope: bytes) -> bytes:
        """还原 SRSA 外层封装。首次调用时顺便恢复公钥模数。"""

        if len(envelope) != 272:
            raise ValueError(f"尚不支持该长度的登录封装: {len(envelope)}")
        if self._modulus is None:
            self._recover_modulus(envelope)
        return self._pow_unwrap(envelope)

    def keys(self, envelope: bytes) -> tuple[bytes, bytes]:
        """从登录封装里取出本局的会话 key 与 nonce。"""

        fields = protobuf_fields(self.unwrap(envelope))
        wrapped = value(fields, 3, b"")
        nonce = value(fields, 4, b"")
        key = self._private.decrypt(wrapped, padding.PKCS1v15())
        if len(key) != 32 or len(nonce) != 12:
            raise ValueError("会话初始化结构不符合预期")
        return key, nonce


class Reassembler:
    """把 TCP 段拼成连续字节流，并处理乱序、重传与重叠。"""

    def __init__(self):
        self.base: int | None = None
        self.next = 0
        self.pending: dict[int, bytes] = {}
        self.gap_since: float | None = None

    def feed(self, seq: int, data: bytes, syn: bool = False) -> bytes:
        if syn and self.base is None:
            self.base = (seq + 1) & 0xFFFFFFFF
        if self.base is None or not data:
            return b""
        offset = ((seq + (1 if syn else 0)) - self.base) & 0xFFFFFFFF
        if offset > 0x7FFFFFFF:  # 落在基线之前的旧段
            return b""
        end = offset + len(data)
        if end <= self.next:
            return b""
        if offset < self.next:  # 与已交付的重叠部分丢掉
            data = data[self.next - offset :]
            offset = self.next
        # 同一起点保留更长的那份：重传可能带来更多字节
        if len(self.pending.get(offset, b"")) < len(data):
            self.pending[offset] = data
        result: list[bytes] = []
        while self.pending:
            first = min(self.pending)
            if first > self.next:
                break
            part = self.pending.pop(first)
            skip = self.next - first
            if skip < len(part):
                part = part[skip:]
                result.append(part)
                self.next += len(part)
        if sum(map(len, self.pending.values())) > _REORDER_LIMIT:
            raise ValueError("TCP 乱序缓存超过上限")
        self.gap_since = (self.gap_since or time.time()) if self.pending else None
        return b"".join(result)


class State:
    """后端对外暴露的全部状态；页面与统计都从这里读。"""

    def __init__(self, record_writer=None):
        self.lock = threading.RLock()
        self.record_writer = record_writer
        self.started = time.time()
        self.status = "初始化解码器"
        self.capture_ready = False
        self.interface = ""
        self.packets = 0
        self.drops = 0
        self.frames = 0
        self.moves = 0
        self.objects = 0
        self.leaders = 0
        self.last: dict[str, Any] | None = None
        self.points: deque = deque(maxlen=1200)
        self.events: deque = deque(maxlen=40)
        self.recent: deque = deque(maxlen=14)
        self.flows: dict[int, Flow] = {}
        self.travel_poles = TravelPoleStore()
        self.facilities = FacilityStore()
        self.bootstrap_seconds: float | None = None
        self.modulus_seconds: float | None = None
        self.capture_error: str | None = None
        #: 位置写盘失败的原因；非空表示已停止写盘但解码仍在继续
        self.record_error: str | None = None
        #: 位置回调（命名管道等）。**必须不阻塞**——它们在持锁状态下被调用
        self.sinks: list = []
        #: 逐场景观察到的地图名，用来人工核对 scene → 网格 的对应关系
        self.scene_maps: dict[str, Counter] = defaultdict(Counter)
        self.ws = {"status": "未启用", "samples": 0, "lastPosition": None, "error": None}
        self.ws_points: deque = deque(maxlen=1200)

    def event(self, message: str) -> None:
        with self.lock:
            self.events.appendleft({"time": time.time(), "message": message})

    def subscribe(self, sink) -> None:
        """注册一个"每解出一条主控坐标就调一次"的回调。

        回调在 ``self.lock`` 持有期间被调用，**只许入队、不许做 IO 或回头访问本对象**。
        """

        with self.lock:
            self.sinks.append(sink)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            flows = []
            for flow in list(self.flows.values())[-12:]:
                gaps = {name: len(stream.pending) for name, stream in flow.streams.items()}
                status = "等待 TCP 补包" if any(gaps.values()) and not flow.failed else flow.status
                flows.append(
                    {
                        "id": flow.id,
                        "client": f"{flow.client[0]}:{flow.client[1]}",
                        "server": f"{flow.server[0]}:{flow.server[1]}",
                        "status": status,
                        "frames": flow.frames,
                        "positions": flow.leaders,
                        "gaps": gaps,
                        "lastPacket": flow.last_time,
                    }
                )
            return {
                "started": self.started,
                "status": self.status,
                "captureReady": self.capture_ready,
                "interface": self.interface,
                "packets": self.packets,
                "queueDrops": self.drops,
                "frames": self.frames,
                "moveMessages": self.moves,
                "objectPositions": self.objects,
                "leaderPositions": self.leaders,
                "lastPosition": self.last,
                "trajectory": list(self.points),
                "events": list(self.events),
                "recentMessages": list(self.recent),
                "flows": flows,
                "bootstrapSeconds": self.bootstrap_seconds,
                "modulusSeconds": self.modulus_seconds,
                "captureError": self.capture_error,
                "recordError": self.record_error,
                "travelPoles": self.travel_poles.summary(),
                "facilities": self.facilities.summary(),
                "sceneMaps": self.scene_maps_summary(),
                "ws": {**self.ws, "trajectory": list(self.ws_points)},
                "now": time.time(),
            }

    def scene_maps_summary(self) -> list[dict[str, Any]]:
        """`sceneNumId` 与地图名的共现统计，用来核对场景与网格的对应关系。

        ``maps`` 是**观测**到的共现（来自官方地图 WS 对照）；``declared`` 是本地场景表
        里的**静态**解析（关卡 id 与所属地图），两者可能不一致，都摆出来而不是互相覆盖。
        """

        rows = []
        for scene, counter in sorted(self.scene_maps.items(), key=lambda item: str(item[0])):
            info = resolve_scene(scene)
            rows.append(
                {
                    "scene": int(scene) if str(scene).lstrip("-").isdigit() else scene,
                    "total": sum(counter.values()),
                    "maps": [{"mapId": name or "(未知)", "count": count} for name, count in counter.most_common()],
                    "declared": info.to_dict() if info else None,
                }
            )
        return rows


class Flow:
    """一条游戏 TCP 连接的解码状态。"""

    def __init__(self, identity: int, client, server, state: State, bootstrap: Bootstrap):
        self.id = identity
        self.client = client
        self.server = server
        self.state = state
        self.bootstrap = bootstrap
        self.streams = {name: Reassembler() for name in ("out", "in")}
        self.buffers = {name: bytearray() for name in ("out", "in")}
        self.ciphers: dict[str, Any] = {}
        self.fragments: dict[str, dict] = {"out": {}, "in": {}}
        self.initial_out = False
        self.failed = False
        self.status = "等待登录初始化"
        self.frames = 0
        self.leaders = 0
        self.last_time = time.time()
        self.callback_at: float | None = None
        self.processing_at: float | None = None
        self.processing_perf: float | None = None
        self.replayed = False

    def receive(self, direction: str, packet) -> None:
        self.last_time = float(packet.time)
        tcp = packet[TCP_LAYER]
        if self.failed:
            return
        stream = self.streams[direction]
        if stream.base is None and not int(tcp.flags) & 2 and tcp_payload(packet):
            # 没有 SYN 起点就说明抓包晚于这条连接：流状态无法确定，明确拒绝而不是猜。
            self.status = "缺少连接起点，请重新启动游戏"
            return
        try:
            data = stream.feed(tcp.seq, tcp_payload(packet), bool(int(tcp.flags) & 2))
            self.buffers[direction].extend(data)
            if len(self.buffers[direction]) > _BUFFER_LIMIT:
                raise ValueError("等待初始化的缓冲区超过上限")
            self.consume(direction)
            if int(tcp.flags) & 5:
                self.status = "连接已结束"
        except Exception as exc:
            self.failed = True
            self.status = "解码停止：" + str(exc)[:160]
            self.ciphers.clear()
            self.state.event(f"连接 {self.id}：{self.status}")

    def consume(self, direction: str) -> None:
        buffer = self.buffers[direction]
        while len(buffer) >= 3:
            head_length = buffer[0]
            body_length = int.from_bytes(buffer[1:3], "little")
            size = 3 + head_length + body_length
            if head_length < 1:
                raise ValueError("帧头长度无效")
            if len(buffer) < size:
                return
            if not self.ciphers:
                if direction == "out":
                    self._consume_initial_request(buffer, head_length, size)
                    continue
                self._consume_initial_response(buffer, head_length, size)
                continue
            if direction == "out" and not self.initial_out:
                raise ValueError("未捕获初始请求，无法确定上行流状态")
            self._consume_crypted(direction, buffer, head_length, size)

    def _consume_initial_request(self, buffer: bytearray, head_length: int, size: int) -> None:
        """上行第一个明文帧：只校验并按长度跳过，不需要解开它的原生封装。"""

        if self.initial_out:
            return
        head = protobuf_fields(bytes(buffer[3 : 3 + head_length]))
        if value(head, 1) != 13:
            raise ValueError("未识别的初始登录请求")
        self.initial_out = True
        body_length = size - 3 - head_length
        del buffer[:size]
        self.note(13, "out", body_length, False)

    def _consume_initial_response(self, buffer: bytearray, head_length: int, size: int) -> None:
        """下行的登录响应：解开 SRSA 外层与 RSA 包装，建立双向流状态。"""

        head = protobuf_fields(bytes(buffer[3 : 3 + head_length]))
        if value(head, 1) != 1:
            raise ValueError("未识别的初始登录响应")
        key, nonce = self.bootstrap.keys(bytes(buffer[3 + head_length : size]))
        self.ciphers = {name: ChaCha20.new(key=key, nonce=nonce) for name in ("out", "in")}
        for cipher in self.ciphers.values():
            cipher.seek(_CIPHER_SEEK_BYTES)
        del key, nonce
        body_length = size - 3 - head_length
        del buffer[:size]
        self.status = "正在解码"
        with self.state.lock:
            self.state.travel_poles.begin_session(self.id)
            self.state.facilities.begin_session(self.id)
        self.note(1, "in", body_length, False)
        # 公钥模数是懒恢复的（用这条登录响应当样本），所以它的耗时要到这时才知道
        self.state.modulus_seconds = self.bootstrap.modulus_seconds
        self.state.event(f"连接 {self.id} 登录初始化成功，开始持续解码")

    def _consume_crypted(self, direction: str, buffer: bytearray, head_length: int, size: int) -> None:
        decoded = self.ciphers[direction].decrypt(bytes(buffer[3:size]))
        del buffer[:size]
        head = protobuf_fields(decoded[:head_length])
        message_id = value(head, 1, -1)
        if not isinstance(message_id, int) or not 0 <= message_id <= 100000:
            raise ValueError("解密后的消息号无效")
        body = decoded[head_length:]
        if value(head, 6):
            body = lz4_decompress(body, uncompressed_size=16 * 1024 * 1024)
        total = value(head, 4, 1)
        index = value(head, 5)
        if total > 1:
            if not 0 <= index < total <= 4096:
                raise ValueError("分片索引无效")
            group = self.fragments[direction]
            if index == 0:
                group[message_id] = {}
            if message_id not in group or index in group[message_id]:
                raise ValueError("分片顺序无效")
            group[message_id][index] = body
            if len(group[message_id]) != total:
                self.note(message_id, direction, size - 3 - head_length, False)
                return
            body = b"".join(group[message_id][i] for i in range(total))
            del group[message_id]
        self.note(message_id, direction, size - 3 - head_length, False)
        self.business(message_id, body, direction, False)

    def note(self, message_id: int, direction: str, length: int, merged: bool) -> None:
        with self.state.lock:
            if not merged:
                self.frames += 1
                self.state.frames += 1
            self.state.recent.appendleft(
                {
                    "time": self.last_time,
                    "flow": self.id,
                    "direction": direction,
                    "id": message_id,
                    "bytes": length,
                    "merged": merged,
                }
            )

    def business(self, message_id: int, body: bytes, direction: str, merged: bool) -> None:
        if message_id == 500 and direction == "out":
            self._unpack_merged(body, direction)
        elif message_id == 81 and direction == "out":
            self._extract_positions(body, merged)
        elif direction == "in" and message_id in (211, 212, 221, 222, 223, 227):
            # 工厂报文是坐标解码的旁路：快照自己吞掉解析失败，不向这里抛异常。
            with self.state.lock:
                self.state.facilities.apply(self.id, message_id, body, self.last_time)
                if message_id != 227:
                    self.state.travel_poles.apply(self.id, message_id, body, self.last_time)

    def _unpack_merged(self, body: bytes, direction: str) -> None:
        """展开 ``CS_MERGE_MSG``：里面每个子消息都有自己的头与可选 LZ4。"""

        raw = value(protobuf_fields(body), 1, b"")
        at = 0
        while at < len(raw):
            if at + 3 > len(raw):
                raise ValueError("合并帧前缀不完整")
            head_length = raw[at]
            body_length = int.from_bytes(raw[at + 1 : at + 3], "little")
            end = at + 3 + head_length + body_length
            if not head_length or end > len(raw):
                raise ValueError("合并帧长度无效")
            head = protobuf_fields(raw[at + 3 : at + 3 + head_length])
            child = value(head, 1, -1)
            child_body = raw[at + 3 + head_length : end]
            if value(head, 6):
                child_body = lz4_decompress(child_body, uncompressed_size=16 * 1024 * 1024)
            if child == 500:
                raise ValueError("嵌套合并帧尚未支持")
            self.note(child, direction, body_length, True)
            self.business(child, child_body, direction, True)
            at = end

    def _extract_positions(self, body: bytes, merged: bool) -> None:
        """消息 81：`move_info[i]` 里 `i == leader_index` 的那条是当前操控角色。

        朝向与速度本来就在报文里（``MOTION_INFO.rotation`` / ``.speed``），一并取出来
        ——它们是游戏上报的真值，比从画面推断可靠。
        """

        message = PositionMessage.FromString(body)
        with self.state.lock:
            self.state.moves += 1
            self.state.objects += len(message.move_info)
            for index, entry in enumerate(message.move_info):
                if index != message.leader_index:
                    continue
                position = entry.motion_info.position
                rotation = entry.motion_info.rotation
                speed = entry.motion_info.speed
                scene_info = resolve_scene(entry.scene_num_id)
                decoded_at = time.time()
                record = PositionRecord(
                    time=self.last_time,
                    flow=self.id,
                    object_id=str(entry.objid),
                    scene=entry.scene_num_id,
                    level_id=scene_info.level_id if scene_info else "",
                    level_name=scene_info.level_name if scene_info else "",
                    dungeon_name=scene_info.dungeon_name if scene_info else "",
                    map_id=scene_info.map_id if scene_info else "",
                    map_name=scene_info.map_name if scene_info else "",
                    x=position.x,
                    y=position.y,
                    z=position.z,
                    heading=rotation.y,
                    speed=(speed.x * speed.x + speed.y * speed.y + speed.z * speed.z) ** 0.5,
                    state=entry.motion_info.state,
                    merged=merged,
                    sample_id=self.state.leaders + 1,
                    capture_at=self.last_time,
                    callback_at=self.callback_at,
                    processing_started_at=self.processing_at,
                    decoded_at=decoded_at,
                    decode_ms=(time.perf_counter() - self.processing_perf) * 1000 if self.processing_perf else None,
                    queue_ms=max(0, (self.processing_at - self.callback_at) * 1000)
                    if self.callback_at and self.processing_at
                    else None,
                    capture_to_decoded_ms=max(0, (decoded_at - self.last_time) * 1000) if not self.replayed else None,
                    replayed=self.replayed,
                    game_server_time=entry.server_time,
                )
                payload = record.to_dict()
                self.leaders += 1
                self.state.leaders += 1
                self.state.last = payload
                self.state.points.append(payload)
                self.state.scene_maps[str(record.scene)][self._observed_map_id()] += 1
                for sink in tuple(self.state.sinks):
                    try:
                        sink(payload)
                    except Exception as exc:  # 推送给消费方失败不该拖垮解码
                        self.state.event(f"推送坐标失败：{str(exc)[:120]}")
                if self.state.record_writer and not self.state.record_error:
                    try:
                        self.state.record_writer.write(json.dumps(payload, ensure_ascii=False) + "\n")
                        self.state.record_writer.flush()
                    except (OSError, TypeError, ValueError) as exc:
                        # 写盘失败（磁盘满、权限、编码）不该把整条解码链拖垮，但也**不能**
                        # 静默：记一次并停写，让看板上看得见。
                        self.state.record_error = str(exc)[:200]
                        self.state.event(f"位置写盘失败，已停止写入（解码继续）：{exc}")

    def _observed_map_id(self) -> str:
        """后端若同时跑着官方地图 WS，用它的 mapId 作为场景的对照真值。"""

        last = self.state.ws.get("lastPosition")
        if isinstance(last, dict):
            return str(last.get("mapId") or "")
        return ""


class Engine:
    """按 TCP 连接分派报文到各自的 :class:`Flow`。"""

    #: 游戏主连接端口（实测出现过 30000 与 40000）
    GAME_PORTS = (30000, 40000)

    def __init__(self, state: State, bootstrap: Bootstrap, ports: tuple[int, ...] | None = None):
        self.state = state
        self.bootstrap = bootstrap
        self.ports = tuple(ports) if ports else self.GAME_PORTS
        self.flows: dict[tuple, Flow] = {}

    def receive(self, packet, callback_at: float | None = None, replayed: bool = False) -> None:
        processing_at = time.time()
        processing_perf = time.perf_counter()
        if IP_LAYER not in packet or TCP_LAYER not in packet:
            return
        ip, tcp = packet[IP_LAYER], packet[TCP_LAYER]
        if not any(port in (tcp.sport, tcp.dport) for port in self.ports):
            return
        is_outbound = tcp.dport in self.ports
        client = (ip.src, tcp.sport) if is_outbound else (ip.dst, tcp.dport)
        server = (ip.dst, tcp.dport) if is_outbound else (ip.src, tcp.sport)
        direction = "out" if is_outbound else "in"
        key = (client, server)
        with self.state.lock:
            self.state.packets += 1
            if key not in self.flows:
                identity = len(self.state.flows) + 1
                flow = Flow(identity, client, server, self.state, self.bootstrap)
                self.flows[key] = flow
                self.state.flows[identity] = flow
                self.state.event(f"发现游戏连接 {identity}：{server[0]}:{server[1]}")
            flow = self.flows[key]
            flow.callback_at = callback_at
            flow.processing_at = processing_at
            flow.processing_perf = processing_perf
            flow.replayed = replayed
            flow.receive(direction, packet)
