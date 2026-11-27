"""抓包后端的命令行入口。

两个子命令：

- ``serve``：抓包 + 看板（日常用这个）
- ``selftest``：拿一份完整抓包回放，核对解码结果与预期一致（验证用）

``selftest`` 是判断"这套解码在这台机器、这个客户端版本上还行不行"的唯一可靠办法，
改完代码先跑它。
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .pipe_server import DEFAULT_PIPE_NAME

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8766


def _default_game_directory() -> Path | None:
    """按常见安装位置探测客户端目录，允许用 ``EF_GAME_DIR`` 覆盖。"""

    override = os.environ.get("EF_GAME_DIR")
    if override:
        return Path(override)
    candidates = [
        Path("D:/GAMES/Endfield Game"),
        Path("E:/Hypergryph Launcher/games/Endfield Game"),
        Path("C:/Games/Endfield Game"),
        Path("D:/Program Files/Endfield Game"),
    ]
    for path in candidates:
        if (path / "GameAssembly.dll").is_file():
            return path
    return None


def _require_game_directory(explicit: str | None) -> Path:
    directory = Path(explicit) if explicit else _default_game_directory()
    if directory is None or not (directory / "GameAssembly.dll").is_file():
        raise SystemExit(
            "找不到终末地客户端目录。请用 --game-dir 指定，或设置环境变量 EF_GAME_DIR 指向\n"
            "含 GameAssembly.dll 与 Endfield_Data/il2cpp_data/Metadata/global-metadata.dat 的目录。"
        )
    return directory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endfield-capture-backend",
        description="终末地抓包坐标后端：被动抓包、离线解码、本地看板",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    capture = sub.add_parser("capture", help="仅录制游戏流量到 pcap，按 Ctrl+C 结束")
    capture.add_argument("output", type=Path, help="新建的 pcap 文件路径")
    capture.add_argument("--interface", help="抓包网卡（网卡名或 IP）")

    serve = sub.add_parser("serve", help="抓包并启动本地看板")
    serve.add_argument("--host", default=DEFAULT_HOST)
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve.add_argument("--game-dir", help="客户端安装目录（默认自动探测）")
    serve.add_argument("--interface", help="抓包网卡（网卡名或 IP）；留空按默认路由自动选择")
    serve.add_argument("--runs-dir", help="运行产物目录，默认 ./runs")
    serve.add_argument(
        "--seed-pcap",
        help="先开始新抓包，再重放这份旧捕获以接管一个已经在跑的游戏会话（重放样本不计入在线延迟）",
    )
    serve.add_argument(
        "--no-map-ws",
        action="store_true",
        help="不启用官方地图 WS 对照（默认启用；启用需要在 ok-end-field 里配置账号 content）",
    )
    serve.add_argument(
        "--no-dashboard",
        action="store_true",
        help="不提供网页看板，只留 /api/*（给 ok-end-field 或后台运行时选这个；可以不打 dashboard.html）",
    )
    serve.add_argument(
        "--pipe",
        nargs="?",
        const=DEFAULT_PIPE_NAME,
        default=None,
        help=f"额外把坐标推到 Windows 命名管道（不带值时用 {DEFAULT_PIPE_NAME}）",
    )
    serve.add_argument(
        "--no-http",
        action="store_true",
        help="连 HTTP 服务也不起，只用命名管道（需要 --pipe；这样不占任何端口）",
    )
    serve.add_argument(
        "--ok-end-field",
        help="ok-end-field 仓库路径（仅用于地图 WS 对照，默认自动探测同级目录）",
    )
    serve.add_argument("--account", default="", help="地图 WS 对照使用的账号（手机号）；配置里有多份 content 时必须指定")
    serve.add_argument("--content", default="", help="直接指定地图 WS content，优先于 --account")

    selftest = sub.add_parser("selftest", help="用完整抓包回放核对解码结果")
    selftest.add_argument("pcap", help="完整会话抓包（必须含登录握手）")
    selftest.add_argument("--game-dir", help="客户端安装目录（默认自动探测）")
    selftest.add_argument(
        "--expect",
        help="预期结果 JSON，默认用内置的参考数值（137 移动消息 / 229 对象位置 / 39 主控位置）",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "capture":
        from scapy.all import PcapWriter, sniff

        from .server import CAPTURE_FILTER, pick_interface

        iface = pick_interface(args.interface)
        with args.output.open("xb") as stream, PcapWriter(stream, sync=True) as writer:
            sniff(
                iface=iface,
                filter=CAPTURE_FILTER,
                prn=writer.write,
                store=False,
                started_callback=lambda: print(f"正在监听 {iface.name}，写入 {args.output}，按 Ctrl+C 结束", flush=True),
            )
        return 0
    if args.command == "serve":
        from .server import serve

        return serve(args)
    if args.command == "selftest":
        from .selftest import run_selftest

        return run_selftest(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
