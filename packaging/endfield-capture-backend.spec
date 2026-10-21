# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 规格：把后端打成**单个可执行文件**（无界面模式够用）。

    uv run --with pyinstaller pyinstaller packaging/endfield-capture-backend.spec --noconfirm

产物是 ``dist/endfield-capture-backend.exe``（onefile）。三样东西**打不进去**，必须在目标
机器上单独准备：

* **Npcap 驱动** —— 抓包必需（安装时勾 "WinPcap API-compatible Mode"），驱动不属于 Python 包；
* **游戏客户端** —— ``GameAssembly.dll`` 与 ``global-metadata.dat`` 只从本机客户端读；
* **ok-end-field** —— 只有启用官方地图 WS 对照时才需要；配合本二进制一般用
  ``--no-map-ws`` 跑。

运行时资源随包带，不用额外准备：``data/scene_index.json``（场景表）、
两服各自的 ``data/rsa_modulus*.json``（公钥模数）与 ``static/dashboard.html``（看板页面）。

**故意排除 ``unicorn`` / ``capstone``**：它们只服务 ``endfield_capture.srsa`` 那个离线
模拟器，用来恢复公钥模数；而 unicorn 的 JIT 在 PyInstaller 冻结出的进程里会直接崩掉
（``0xC0000409``，连 traceback 都没有）。模数改成从 ``data/rsa_modulus.json`` 读之后就
用不着模拟器了，于是冻结版**不带**这两个包——一并省掉 65 MB。运行时若两者都没有
（数据缺失 + 没有模拟器），解码器会明确报错让人去生成数据，而不是安静地解出错的东西。
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent  # packaging/ 的上一级 = 仓库根
SRC = ROOT / "src"
PKG = SRC / "endfield_capture"
DATA = PKG / "data"
STATIC = PKG / "static"

#: 这些包靠动态导入，不显式列出来会被漏掉
HIDDEN = [
    "scapy.layers.all",
    "scapy.layers.inet",
    "scapy.layers.l2",
    "scapy.arch.windows",
    "Crypto.Cipher.ChaCha20",
    "cryptography.hazmat.backends.openssl",
    "lz4.block",
    "google.protobuf.descriptor_pb2",
    "google.protobuf.message_factory",
]

#: 与运行无关的大件，剔掉能省几十 MB；unicorn / capstone 见模块 docstring
EXCLUDES = [
    "unicorn",
    "capstone",
    "tkinter",
    "PyQt5",
    "PyQt6",
    "PySide2",
    "PySide6",
    "matplotlib",
    "pandas",
    "IPython",
    "notebook",
    "pytest",
    "setuptools",
    "pip",
    "wheel",
]

#: 抓包要 scapy 的 arch/windows 子模块，动态加载的部分靠 collect_submodules 兜住
HIDDEN += collect_submodules("scapy.layers") + collect_submodules("scapy.arch")

a = Analysis(
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=[
        (str(DATA / "scene_index.json"), "endfield_capture/data"),
        (str(DATA / "rsa_modulus.json"), "endfield_capture/data"),
        (str(DATA / "rsa_modulus_international.json"), "endfield_capture/data"),
        # 看板页面。**必须打进去**：server.py 走 ``DASHBOARD_HTML.read_bytes()``，文件不在
        # 就抛 FileNotFoundError，客户端拿到的是连接被直接断开（不是干净的 500）。此前这里
        # 漏了它，于是冻结版只能在 ``--no-dashboard`` 下用——而 README 只是"说明"了那个参数，
        # 没说必需，拿到 exe 的人打开 / 就会撞上。只多 17 KB。
        (str(STATIC / "dashboard.html"), "endfield_capture/static"),
    ],
    hiddenimports=HIDDEN,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="endfield-capture-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
