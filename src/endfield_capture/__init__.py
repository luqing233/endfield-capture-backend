"""终末地抓包坐标后端：被动抓包、离线解码、本地看板。

应用侧（ok-end-field）只通过本地 HTTP 读这个后端的位置，本包不含任何应用代码。

只做被动旁观：不注入、不 Hook、不读游戏进程内存、不改游戏文件。
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.4"
