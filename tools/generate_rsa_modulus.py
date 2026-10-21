"""离线跑一次原生接收路径模拟，把恢复出的**公钥模数**存成运行时读的数据。

**这是一次性的离线步骤**：运行时（``endfield_capture.decoder.Bootstrap``）只读 JSON，
自己不解包、不模拟。客户端更新之后重跑本脚本即可。

为什么要有这一步：恢复模数靠的是把客户端 DLL 的机器码放进 unicorn 里跑一遍。unicorn 的
JIT 在 PyInstaller 冻结出来的进程里会直接崩掉（``0xC0000409``，连 traceback 都没有），
所以打包版故意**不带** unicorn / capstone，改读这里生成的 JSON。模数只跟客户端版本有关，
而客户端版本已经被 SHA-256 钉死，因此离线解一次就够用。

存下来的只有**公钥模数**（公开材料，exp 恒为 65537），不含私钥、会话 key 或 nonce。

需要一份**含登录握手**的抓包当输入：模拟器必须拿到一条真实的 272 字节登录封装才会跑通
（喂全零之类的假数据它会提前返回，恢复不出模数）。默认取 ``runs/`` 里最新的一份。

    python tools/generate_rsa_modulus.py                       # 自动挑最新抓包，写包内 data/
    python tools/generate_rsa_modulus.py --pcap <路径>          # 指定抓包
    python tools/generate_rsa_modulus.py --game-dir <客户端目录>
    python tools/generate_rsa_modulus.py --dry-run             # 只打印，不写文件
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from endfield_capture import srsa  # noqa: E402
from endfield_capture.cli import _require_game_directory  # noqa: E402
from endfield_capture.decoder import (  # noqa: E402
    Bootstrap,
    Engine,
    State,
)
from endfield_capture.pe_image import PeImage  # noqa: E402
from endfield_capture.selftest import _read_packets  # noqa: E402

SCHEMA_VERSION = 1

#: 预期的模数位数。不是 2048 位说明抓到的那条不是登录响应，或者客户端换了密钥长度。
EXPECTED_MODULUS_BITS = 2048


class _CaptureBootstrap(Bootstrap):
    """跑解码的同时把第一条登录封装抄下来。

    两条刻意的行为：

    * ``_load_stored_modulus`` 恒返回 ``None`` —— **总是现场模拟**。否则在有 data 文件的
      机器上重跑本脚本会「拿旧值验证旧值」，客户端换了也照样报成功。
    * 只在第一次 ``unwrap`` 时记录；登录封装每条连接只出现一次，第一条就是样本。
    """

    def __init__(self, game_directory: Path):
        self.captured: list[bytes] = []
        super().__init__(game_directory)

    def _load_stored_modulus(self) -> int | None:
        return None

    def unwrap(self, envelope: bytes) -> bytes:
        if not self.captured:
            self.captured.append(envelope)
        return super().unwrap(envelope)


def _latest_capture() -> Path | None:
    """``runs/`` 下最新的一份 ``capture.pcap``（没有就返回 ``None``）。"""

    candidates = sorted(REPO_ROOT.glob("runs/*/*/capture.pcap"), key=lambda path: path.stat().st_mtime)
    return candidates[-1] if candidates else None


def _capture_envelope(pcap: Path, game_directory: Path) -> tuple[_CaptureBootstrap, bytes]:
    """回放抓包直到第一条登录封装出现，返回承载它的 bootstrap 与封装本身。"""

    bootstrap = _CaptureBootstrap(game_directory)
    packets = _read_packets(pcap)
    engine = Engine(State(), bootstrap)
    for packet in packets:
        engine.receive(packet)
        if bootstrap.captured:
            break
    if not bootstrap.captured:
        raise SystemExit(
            f"这份抓包里没有登录握手，拿不到登录封装：{pcap}\n"
            "请换一份**从游戏启动前就开始抓**的完整抓包（runs/ 里的 capture.pcap 通常就是）。"
        )
    return bootstrap, bootstrap.captured[0]


def _describe(result: srsa.EmulationResult) -> dict:
    """从模拟状态里挑出「这次跑通了吗」的自证项，写进 JSON 便于日后核对。"""

    checks = [item for item in (result.state or {}).get("modularExponentiationChecks", []) if item.get("captured")]
    return {
        "state": (result.state or {}).get("stop"),
        "blocks": (result.state or {}).get("blocks"),
        "pages": (result.state or {}).get("pages"),
        "seconds": round(result.seconds, 3),
        "transformed_length": len(result.transformed) if result.transformed else None,
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pcap", type=Path, help="含登录握手的完整抓包（默认取 runs/ 里最新的一份）")
    parser.add_argument("--game-dir", help="客户端安装目录（默认自动探测，也可用 EF_GAME_DIR）")
    parser.add_argument("--out", type=Path, help="输出 JSON（默认写入已验证客户端对应的包内 data/）")
    parser.add_argument("--dry-run", action="store_true", help="只打印，不写文件")
    args = parser.parse_args(argv)

    pcap = args.pcap or _latest_capture()
    if pcap is None:
        raise SystemExit("runs/ 下没有 capture.pcap，请用 --pcap 指定一份含登录握手的抓包。")
    if not pcap.is_file():
        raise SystemExit(f"找不到抓包文件 {pcap}")

    game_directory = _require_game_directory(args.game_dir)
    print(f"客户端目录 {game_directory}")
    print(f"抓包       {pcap}")

    bootstrap, envelope = _capture_envelope(pcap, game_directory)
    print(f"登录封装 {len(envelope)} 字节；客户端材料用时 {bootstrap.key_seconds:.2f} s")

    # 解码过程中已经模拟过一次（拿到的就是 bootstrap.modulus）；这里再独立跑一遍，
    # 一是拿完整的模拟统计写进 JSON，二是把两次结果对一下，防止懒恢复那条路悄悄走了别的分支。
    image = PeImage(game_directory / "GameAssembly.dll")
    result = srsa.emulate_receive_entry(image, envelope)
    if not result.ok or result.modulus is None:
        reason = (result.state or {}).get("stop") or (result.state or {}).get("error")
        raise SystemExit(f"原生接收路径模拟未跑通：{reason}")
    if result.modulus != bootstrap.modulus:
        raise SystemExit(
            "两次模拟恢复出的模数不一致：\n"
            f"  解码过程中：{bootstrap.modulus.bit_length()} 位\n"
            f"  独立重跑：  {result.modulus.bit_length()} 位\n"
            "这说明模拟不稳定，先查清楚再写文件。"
        )
    if result.modulus.bit_length() != EXPECTED_MODULUS_BITS:
        raise SystemExit(f"模数 {result.modulus.bit_length()} 位，预期 {EXPECTED_MODULUS_BITS} 位——先查清楚再写文件。")

    # 最后一道自证：纯 Python 的 pow 必须逐字节复现模拟输出，否则这个模数运行时也用不了。
    length = int.from_bytes(envelope[8:12], "little")
    recovered = pow(int.from_bytes(envelope[16:], "big"), 65537, result.modulus).to_bytes(256, "little")[:length]
    if recovered != result.transformed:
        raise SystemExit("纯 Python 模幂结果与模拟输出不一致，拒绝写出这个模数。")

    details = _describe(result)
    print(
        f"模数 {result.modulus.bit_length()} 位，指数 65537；"
        f"模拟 {details['blocks']} 基本块 / {details['pages']} 页 / {details['seconds']} s"
    )
    print(f"自证：纯 Python 模幂输出与模拟输出逐字节一致（{len(recovered)} 字节）")

    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "source": f"SRSA 原生接收入口模拟（RVA {srsa.RECEIVE_ENTRY_RVA:#x}）恢复出的公钥模数",
        "client_dll_sha256": bootstrap.profile.dll_sha256,
        "client_metadata_sha256": bootstrap.profile.metadata_sha256,
        "modulus_hex": f"{result.modulus:x}",
        "modulus_bits": result.modulus.bit_length(),
        "public_exponent": 65537,
        "emulation": details,
    }
    if args.dry_run:
        print("（--dry-run，不写文件）")
        return 0
    output = args.out or bootstrap.modulus_data_path
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"已写入 {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
