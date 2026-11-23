#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""构建脚本：用 PyInstaller 把 gui_app.py 打包成单文件无控制台 exe。

用法：python build.py
产物：ShellCrash规则管理器.exe（工作区根目录）
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXE = "ShellCrash规则管理器"


def place(src, dst):
    """目标正被运行时 Windows 不允许覆盖，先把旧文件改名再落盘。"""
    if not os.path.exists(dst):
        os.rename(src, dst)
        return
    try:
        os.replace(src, dst)
        return
    except OSError:
        pass
    old = dst + ".old"
    for i in range(2, 20):
        if not os.path.exists(old):
            break
        try:
            os.remove(old)
            break
        except OSError:
            old = "%s.%d.old" % (dst, i)
    os.rename(dst, old)
    os.rename(src, dst)
    print("提示：旧版本正在运行，已改名为 %s" % os.path.basename(old))


def build():
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--noconsole",
        "--name", EXE,
        "--distpath", os.path.join(HERE, "dist"),
        "--workpath", os.path.join(HERE, "build"),
        "--specpath", os.path.join(HERE, "build"),
        "--hidden-import", "paramiko",
        "--collect-submodules", "paramiko",
        os.path.join(HERE, "gui_app.py"),
    ]
    print("执行：", " ".join(cmd))
    subprocess.check_call(cmd, cwd=HERE)
    src = os.path.join(HERE, "dist", EXE + ".exe")
    dst = os.path.join(ROOT, EXE + ".exe")
    if os.path.exists(src):
        place(src, dst)
        print("完成：%s（%.1f MB）" % (dst, os.path.getsize(dst) / 1048576))
    else:
        raise SystemExit("未找到产物：%s" % src)


if __name__ == "__main__":
    build()
