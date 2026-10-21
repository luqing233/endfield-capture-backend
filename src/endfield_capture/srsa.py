"""离线模拟客户端原生的 SRSA 接收入口。

登录响应的消息体外面还套了一层原生实现的封装（``Beyond.SRSA.LoadFromFile2``）。
它的入口在受保护代码里，线性反汇编还原不出执行顺序，所以这里把 DLL 指令、常量页、
栈和输入缓冲区放进一个 x86-64 模拟器按需映射 PE 页跑一遍。

**只调用两个系统导入**（``HeapAlloc`` / ``HeapFree``），由本模块自己实现。不加载真实
DLL、不附加进程、不注入、不 Hook 游戏。

模拟出来的结果本身用途有限；真正的收获是从中**恢复出公钥模数**——被处理的大整数与
封装体第 16 字节之后的 256 字节数据按大端解释完全相同，指数恒为 65537，于是可以用
``pow(ciphertext, 65537, modulus)`` 在纯 Python 里复现同样的结果，此后不再需要模拟器。

本模块不导出、不记录任何私钥、会话密钥或 nonce。
"""

from __future__ import annotations

import struct
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_BLOCK,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_MODE_64,
    Uc,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

from .pe_image import PeImage

__all__ = [
    "RECEIVE_ENTRY_RVA",
    "EmulationResult",
    "emulate_receive_entry",
]

#: 两个已验证构建的 LoadFromFile2 原生调用目标（不是解释器内部函数）。
#: 客户端更新后必须同时重新核对接收入口和下方模幂观测点。
RECEIVE_ENTRY_RVA = 0x109EE0

#: 大整数模幂的入口/出口 RVA，用来在运行中捕获一次完整的 ``base^exp mod n``
_POW_ENTRY_RVA = 0x1087F5
_POW_EXIT_RVA = 0x1091FC

#: 参数指针与返回指针各自异或的常量。**这些混淆的是指针，不是数据加密密钥。**
_ARG_POINTER_XOR = 0x971AB5C8FF
_RESULT_POINTER_XOR = 0xF91A4399A0

_STACK_BASE = 0x700000000000
_HEAP_BASE = 0x600000000000
_SENTINEL_BASE = 0x500000000000

#: 安全上限：任何一个超限都会让模拟停下来并如实记录原因，不会无限跑下去
_BLOCK_BUDGET = 2_000_000
_HEAP_BUDGET = 0x100000
_ALLOCATION_LIMIT = 0x80000
_COPY_LIMIT = 0x100000
_TIMEOUT_MICROSECONDS = 30_000_000
_COUNT_LIMIT = 100_000_000


@dataclass
class EmulationResult:
    """一次模拟的产出。``transformed`` 与 ``modulus`` 是调用方真正要的东西。"""

    transformed: bytes | None = None
    #: 从大整数模幂里恢复出的 2048 位公钥模数
    modulus: int | None = None
    seconds: float = 0.0
    state: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.transformed is not None and self.modulus is not None


class _Emulator:
    """承载一次模拟的全部可变状态（原实现用模块级全局变量，这里改成一个实例）。"""

    def __init__(self, image: PeImage, body: bytes):
        self.image = image
        self.body = body
        self.base = image.image_base
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.dis = Cs(CS_ARCH_X86, CS_MODE_64)
        self.state: dict[str, Any] = {
            "blocks": 0,
            "pages": 0,
            "stop": None,
            "inputReads": 0,
            "inputWrites": 0,
            "inputOffsetsRead": set(),
            "apiCalls": [],
            "modularExponentiationChecks": [],
        }
        self.recent: deque = deque(maxlen=40)
        self.visits: Counter = Counter()
        self.imports: dict[int, tuple[str, str]] = {}
        self.fake_imports = _SENTINEL_BASE + 0x10000
        self.next_allocation = _HEAP_BASE + 0x10000
        self.pow_contexts: list[dict[str, Any]] = []
        self.pow_recovered: list[bytes] = []
        self.modulus: int | None = None
        self._setup_memory()
        self._bind_imports()

    # ------------------------------------------------------------------ #
    # 模拟内存
    # ------------------------------------------------------------------ #
    def _setup_memory(self) -> None:
        self.uc.mem_map(_STACK_BASE, 0x200000)
        self.uc.mem_map(_HEAP_BASE, _HEAP_BUDGET)
        self.uc.mem_map(_SENTINEL_BASE, 0x1000)
        self.uc.mem_write(_SENTINEL_BASE, b"\xc3")
        self.uc.mem_map(self.fake_imports, 0x20000)

    def page_map(self, engine, access, address, size, value, data) -> bool:
        """按需把 PE 节映射进模拟内存（原实现就是靠这个省掉整份镜像）。"""

        rva = address - self.base
        section = next(
            (
                s
                for s in self.image.sections
                if s["virtualAddress"] <= rva < s["virtualAddress"] + max(s["virtualSize"], s["rawSize"])
            ),
            None,
        )
        if section is None:
            self.state["stop"] = {
                "reason": "unmapped memory",
                "access": access,
                "address": hex(address),
                "size": size,
            }
            return False
        start = address & ~0xFFF
        engine.mem_map(start, 0x1000)
        raw = bytearray(0x1000)
        lo = max(start - self.base, section["virtualAddress"])
        hi = min(start - self.base + 0x1000, section["virtualAddress"] + section["rawSize"])
        if hi > lo:
            offset = section["rawPointer"] + lo - section["virtualAddress"]
            raw[lo - (start - self.base) : hi - (start - self.base)] = self.image.buf[offset : offset + hi - lo]
        engine.mem_write(start, bytes(raw))
        self.state["pages"] += 1
        return True

    def _bind_imports(self) -> None:
        """把导入表的每个槽位指向一个只执行 ``ret`` 的假桩，由 :meth:`api` 接管。"""

        uc, p, base = self.uc, self.image, self.base
        pe_offset = p.u32_at_file(0x3C)
        optional = pe_offset + 24
        import_directory = p.u32_at_file(optional + 112 + 8)
        descriptor = import_directory
        while True:
            oft, stamp, chain, name, iat = struct.unpack("<IIIII", p.bytes_at_va(base + descriptor, 20))
            if not any((oft, stamp, chain, name, iat)):
                break
            dll = p.c_string_at_va(base + name)
            idx = 0
            while True:
                thunk = p.u64_at_va(base + (oft or iat) + 8 * idx)
                if not thunk:
                    break
                symbol = f"ordinal{thunk & 0xFFFF}" if thunk >> 63 else p.c_string_at_va(base + thunk + 2)
                address = self.fake_imports + 16 * len(self.imports)
                self.imports[address] = (dll, symbol)
                patch = base + iat + 8 * idx
                try:
                    uc.mem_read(patch, 8)
                except UcError:
                    self.page_map(uc, 0, patch, 8, 0, None)
                uc.mem_write(patch, struct.pack("<Q", address))
                uc.mem_write(address, b"\xc3")
                idx += 1
            descriptor += 20

    # ------------------------------------------------------------------ #
    # 钩子
    # ------------------------------------------------------------------ #
    def block(self, engine, address, size, data) -> None:
        self.state["blocks"] += 1
        self.visits[address - self.base] += 1
        self.recent.append((address, size))
        if address == _SENTINEL_BASE:
            self.state["stop"] = {"reason": "returned", "returnValue": hex(engine.reg_read(UC_X86_REG_RAX))}
            engine.emu_stop()
        if self.state["blocks"] >= _BLOCK_BUDGET:
            self.state["stop"] = {"reason": "block budget"}
            engine.emu_stop()

    def input_access(self, engine, access, address, size, value, data) -> None:
        if access == 16:  # UC_MEM_READ
            self.state["inputReads"] += 1
            self.state["inputOffsetsRead"].add(address - _HEAP_BASE)
        else:
            self.state["inputWrites"] += 1

    def big_integer(self, address: int) -> int:
        capacity, used, pointer = struct.unpack("<iiQ", self.uc.mem_read(address, 16))
        assert 0 <= capacity <= 2048 and abs(used) <= capacity
        number = int.from_bytes(self.uc.mem_read(pointer, abs(used) * 4), "little") if used else 0
        return -number if used < 0 else number

    def track_pow(self, engine, address, size, data) -> None:
        """进入模幂时记下操作数，退出时用 Python ``pow`` 复算并比对。"""

        if address == self.base + _POW_ENTRY_RVA:
            try:
                item = {
                    "base": self.big_integer(engine.reg_read(UC_X86_REG_RSI)),
                    "exponent": self.big_integer(engine.reg_read(UC_X86_REG_RDI)),
                    "modulus": self.big_integer(engine.reg_read(UC_X86_REG_R9)),
                    "output": struct.unpack("<Q", engine.mem_read(engine.reg_read(UC_X86_REG_RSP) + 0x100, 8))[0],
                }
                self.pow_contexts.append(item)
            except (UcError, AssertionError):
                self.state["modularExponentiationChecks"].append({"captured": False})
            return
        if not self.pow_contexts:
            return
        item = self.pow_contexts.pop()
        try:
            actual = self.big_integer(item["output"])
            expected = pow(item["base"], item["exponent"], item["modulus"])
            self.modulus = item["modulus"]
            recovered = expected.to_bytes((item["modulus"].bit_length() + 7) // 8, "big")
            self.pow_recovered.append(recovered)
            padding_end = recovered.find(b"\0", 2)
            padding_type = (
                recovered[1] if recovered[0] == 0 and recovered[1] in (1, 2) and padding_end >= 10 else None
            )
            self.state["modularExponentiationChecks"].append(
                {
                    "captured": True,
                    "baseBits": item["base"].bit_length(),
                    "exponentBits": item["exponent"].bit_length(),
                    "modulusBits": item["modulus"].bit_length(),
                    "matchesPythonPow": actual == expected,
                    "standardPublicExponent65537": item["exponent"] == 65537,
                    "operandMatchesCiphertextBigEndian": item["base"] == int.from_bytes(self.body[16:], "big"),
                    "operandMatchesCiphertextLittleEndian": item["base"] == int.from_bytes(self.body[16:], "little"),
                    "pkcs1PaddingType": padding_type,
                    "paddingBytes": padding_end - 2 if padding_type else None,
                    "type1PaddingAllFF": all(byte == 255 for byte in recovered[2:padding_end])
                    if padding_type == 1
                    else None,
                }
            )
        except (UcError, AssertionError, ValueError):
            self.state["modularExponentiationChecks"].append({"captured": True, "comparisonCompleted": False})

    def api(self, engine, address, size, data) -> None:
        """只实现被实际用到的那几个导入；遇到别的就停下并记下来。"""

        dll, symbol = self.imports.get(address, ("unknown", "unknown"))
        a = engine.reg_read(UC_X86_REG_RCX)
        b = engine.reg_read(UC_X86_REG_RDX)
        c = engine.reg_read(UC_X86_REG_R8)
        self.state["apiCalls"].append({"dll": dll, "symbol": symbol})
        if symbol in ("HeapAlloc", "malloc", "calloc", "VirtualAlloc"):
            length = c if symbol == "HeapAlloc" else a * b if symbol == "calloc" else b if symbol == "VirtualAlloc" else a
            if length > _ALLOCATION_LIMIT:
                self.state["stop"] = {"reason": "oversized allocation", "symbol": symbol, "length": length}
                engine.emu_stop()
                return
            result = self.next_allocation
            self.next_allocation += (max(length, 1) + 15) & ~15
            if self.next_allocation > _HEAP_BASE + _HEAP_BUDGET:
                self.state["stop"] = {"reason": "heap budget"}
                engine.emu_stop()
                return
            self.state["apiCalls"][-1]["allocationLength"] = length
        elif symbol in ("HeapFree", "VirtualFree", "CloseHandle"):
            result = 1
        elif symbol in (
            "free",
            "EnterCriticalSection",
            "LeaveCriticalSection",
            "InitializeCriticalSection",
            "DeleteCriticalSection",
        ):
            result = 0
        elif symbol == "GetProcessHeap":
            result = 0xDEAD0000
        elif symbol in ("memcpy", "memmove", "memset"):
            if c > _COPY_LIMIT:
                self.state["stop"] = {"reason": "copy budget", "symbol": symbol, "length": c}
                engine.emu_stop()
                return
            engine.mem_write(a, bytes([b & 255]) * c if symbol == "memset" else bytes(engine.mem_read(b, c)))
            result = a
        else:
            self.state["stop"] = {"reason": "unsupported import", "dll": dll, "symbol": symbol}
            engine.emu_stop()
            return
        engine.reg_write(UC_X86_REG_RAX, result)
        sp = engine.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack("<Q", engine.mem_read(sp, 8))[0]
        engine.reg_write(UC_X86_REG_RSP, sp + 8)
        engine.reg_write(UC_X86_REG_RIP, ret)

    # ------------------------------------------------------------------ #
    # 跑一次
    # ------------------------------------------------------------------ #
    def run(self) -> tuple[bytes | None, dict[str, Any]]:
        uc = self.uc
        uc.mem_write(_HEAP_BASE, self.body + b"\0" * 0x1000)
        top = _STACK_BASE + 0x1FF008
        uc.mem_write(top, struct.pack("<Q", _SENTINEL_BASE))
        uc.reg_write(UC_X86_REG_RSP, top)
        uc.reg_write(UC_X86_REG_RCX, _HEAP_BASE ^ _ARG_POINTER_XOR)
        uc.reg_write(UC_X86_REG_RDX, len(self.body))
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self.page_map)
        uc.hook_add(UC_HOOK_BLOCK, self.block)
        uc.hook_add(UC_HOOK_CODE, self.api, begin=self.fake_imports, end=self.fake_imports + 0x1FFFF)
        uc.hook_add(UC_HOOK_CODE, self.track_pow, begin=self.base + _POW_ENTRY_RVA, end=self.base + _POW_ENTRY_RVA)
        uc.hook_add(UC_HOOK_CODE, self.track_pow, begin=self.base + _POW_EXIT_RVA, end=self.base + _POW_EXIT_RVA)
        uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self.input_access,
            begin=_HEAP_BASE,
            end=_HEAP_BASE + len(self.body) - 1,
        )
        started = time.time()
        try:
            uc.emu_start(self.base + RECEIVE_ENTRY_RVA, _SENTINEL_BASE, timeout=_TIMEOUT_MICROSECONDS, count=_COUNT_LIMIT)
        except UcError as exc:
            self.state["error"] = str(exc)
        self.state["seconds"] = time.time() - started
        self.state["inputOffsetsRead"] = sorted(self.state["inputOffsetsRead"])

        transformed = None
        if uc.reg_read(UC_X86_REG_RIP) == _SENTINEL_BASE:
            self.state["stop"] = {"reason": "returned", "returnValue": hex(uc.reg_read(UC_X86_REG_RAX))}
            result_address = uc.reg_read(UC_X86_REG_RAX) ^ _RESULT_POINTER_XOR
            result_length = struct.unpack("<I", uc.mem_read(result_address, 4))[0]
            if not 0 < result_length <= 0x80000:
                raise ValueError(f"模拟返回的输出长度异常: {result_length}")
            transformed = bytes(uc.mem_read(result_address + 4, result_length))
            self._record_checks(transformed)
        self.state["finalRva"] = hex(uc.reg_read(UC_X86_REG_RIP) - self.base)
        self.state["inputLength"] = len(self.body)
        self.state["recentBlocks"] = []
        for address, size in self.recent:
            try:
                data = bytes(uc.mem_read(address, min(size, 160)))
                self.state["recentBlocks"].append(
                    {
                        "rva": hex(address - self.base),
                        "size": size,
                        "instructions": [
                            f"{ins.address - self.base:x} {ins.mnemonic} {ins.op_str}"
                            for ins in self.dis.disasm(data, address)
                        ],
                    }
                )
            except UcError:
                pass
        self.state["frequentBlocks"] = [(hex(rva), count) for rva, count in self.visits.most_common(15)]
        self.state["ordinaryNativeBlocks"] = [
            (hex(rva), count) for rva, count in self.visits.most_common() if 0 <= rva < 0xEB00000
        ]
        return transformed, self.state

    def _record_checks(self, transformed: bytes) -> None:
        """把"模拟输出"与"用恢复出的模数算出的结果"逐项比对，供调用方自证。"""

        self.state["outputLength"] = len(transformed)
        self.state["rsaRecoveredPayloadMatchesOutput"] = [
            block[block.find(b"\0", 2) + 1 :] == transformed for block in self.pow_recovered
        ]
        self.state["rawRsaPlaintextSliceMatches"] = [
            {"bigEndianOffset": block.find(transformed), "littleEndianOffset": block[::-1].find(transformed)}
            for block in self.pow_recovered
        ]
        self.state["rawRsaFormulaMatchesOutput"] = [
            block[::-1][: len(transformed)] == transformed for block in self.pow_recovered
        ]
        header_words = struct.unpack("<IIII", self.body[:16])
        candidates = [
            ("inputLength", len(self.body)),
            ("ciphertextLength", len(self.body) - 16),
            ("plaintextLength", len(transformed)),
            ("blockBytes128", 128),
            ("blockBytes256", 256),
        ]
        self.state["envelopeHeaderLengthMatches"] = {
            str(index): [name for name, number in candidates if word == number]
            for index, word in enumerate(header_words)
        }
        self.state["envelopeHeaderKeyBitsMatch"] = {
            str(index): word == 2048 for index, word in enumerate(header_words)
        }


def emulate_receive_entry(image: PeImage, body: bytes) -> EmulationResult:
    """跑一遍接收原生变换，返回明文与恢复出的公钥模数。

    Args:
        image: 已读入内存的 ``GameAssembly.dll``。
        body: 登录响应帧的**消息体**（不含 3 字节长度前缀与消息头），本机版本为 272 字节。

    Returns:
        :class:`EmulationResult`；``state`` 里带各项自证用的比对结果，不含任何密钥材料。
    """

    emulator = _Emulator(image, body)
    transformed, state = emulator.run()
    return EmulationResult(
        transformed=transformed,
        modulus=emulator.modulus,
        seconds=float(state.get("seconds") or 0.0),
        state=state,
    )
