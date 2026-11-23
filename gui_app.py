#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShellCrash 规则管理器
------------------------------------------------------------
图形化管理飞牛 NAS 上 ShellCrash 的：
  · 自定义策略组（yamls/proxy-groups.yaml 的增删改，改前自动备份）
  · 自定义规则（yamls/rules.yaml 的增删改，改前自动备份）

技术栈：Python 标准库 http.server + paramiko，单文件 exe。
远程侧用一个内嵌的 Python 助手脚本（root 执行）处理配置读写与外置控制器调用。
"""

import base64
import json
import os
import re
import secrets
import shlex
import socket
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import paramiko
except Exception:  # pragma: no cover
    paramiko = None

APP_NAME = "ShellCrash 规则管理器"
VERSION = "2.1"
PORT_BASE = 8801
TOKEN = secrets.token_urlsafe(18)

SESS = {"client": None, "cfg": {}, "connected": False}
SESS_LOCK = threading.RLock()
STATE = {"last_ping": time.time(), "httpd": None, "port": 0, "page_closed": None}


# ============================================================
# 通用工具
# ============================================================
def any_run_active():
    with SESS_LOCK:
        return bool(SESS.get("busy"))


def shutdown_app(delay=0.5):
    def _do():
        time.sleep(delay)
        try:
            if STATE.get("httpd"):
                STATE["httpd"].shutdown()
        except Exception:
            pass
        os._exit(0)
    threading.Thread(target=_do, daemon=True).start()


def watchdog(idle=180):
    """守护：页面关闭即退出（前端 pagehide 发 /api/bye 置 page_closed）。
    - 收到 bye 后延迟 3 秒退出，若期间页面又发来 ping（例如刷新/重开）则撤销退出。
    - 任务执行中不退出；无任务时若心跳超过 idle 秒（浏览器崩溃等）也兜底退出。"""
    while True:
        time.sleep(1)
        if STATE["httpd"] is None:
            continue
        now = time.time()
        # 正在执行任务：刷新心跳、撤销关闭请求，绝不退出
        if any_run_active():
            STATE["last_ping"] = now
            STATE["page_closed"] = None
            continue
        # 页面明确关闭：等 3 秒（给刷新/重开留窗口），仍无心跳则退出
        pc = STATE.get("page_closed")
        if pc is not None and now - pc > 3:
            shutdown_app(0)
            return
        # 兜底：长时间无心跳（浏览器崩溃、未发出 bye）也退出
        if now - STATE["last_ping"] > idle:
            shutdown_app(0)
            return


def cfg_path():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "ShellCrashRuleManager")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "config.json")


def cfg_load():
    try:
        with open(cfg_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _dpapi(data, encrypt):
    if os.name != "nt":
        raise OSError("非 Windows 环境")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    buf = ctypes.create_string_buffer(bytes(data), len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    fn = crypt32.CryptProtectData if encrypt else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI 失败，错误码 %s" % ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def pwd_seal(pwd):
    try:
        return base64.b64encode(_dpapi(pwd.encode("utf-8"), True)).decode("ascii")
    except Exception:
        return ""


def pwd_open(token):
    if not token:
        return ""
    try:
        return _dpapi(base64.b64decode(token), False).decode("utf-8")
    except Exception:
        return ""


def cfg_save(data):
    try:
        old = cfg_load()
        old.update({k: v for k, v in data.items() if k in ("host", "user", "sudo_pwd", "base")})
        with open(cfg_path(), "w", encoding="utf-8") as f:
            json.dump(old, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def cfg_remember(pwd, on):
    try:
        old = cfg_load()
        if on and pwd:
            sealed = pwd_seal(pwd)
            if sealed:
                old["pwd_enc"] = sealed
        else:
            old.pop("pwd_enc", None)
        with open(cfg_path(), "w", encoding="utf-8") as f:
            json.dump(old, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def cfg_drop(*keys):
    """删掉本地配置里的指定字段（未勾「记住」时清掉上次残留的用户名/密码）。"""
    try:
        old = cfg_load()
        changed = False
        for k in keys:
            if k in old:
                old.pop(k, None)
                changed = True
        if changed:
            with open(cfg_path(), "w", encoding="utf-8") as f:
                json.dump(old, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ============================================================
# SSH 与远程操作（远端只跑 shell，不需要 python3 / base64 / sudo）
# ============================================================
def ssh_connect(host, user, pwd):
    if paramiko is None:
        raise RuntimeError("缺少 paramiko 模块")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if pwd:
        c.connect(host.strip(), 22, user.strip(), pwd, timeout=15,
                  allow_agent=False, look_for_keys=False)
    else:
        # 免密码登录（OpenWrt/iStoreOS 允许 root 的 none 认证）。
        # paramiko 的 connect(password='') 不会触发 none 认证，这里用底层 Transport，
        # 再挂到 SSHClient 上，保证 exec_command / open_channel 都能用。
        import socket as _sock
        _sockobj = _sock.create_connection((host.strip(), 22), timeout=15)
        t = paramiko.Transport(_sockobj)
        t.connect()
        try:
            t.auth_none(user.strip())
        except paramiko.BadAuthenticationType:
            t.auth_password(user.strip(), "")
        if not t.is_authenticated():
            raise RuntimeError("SSH 认证失败（服务端不允许免密登录）")
        c._transport = t
    return c


def run_cmd(client, cmd, timeout=40):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    err = re.sub(r"^\[sudo\][^\n]*\n?", "", err)
    err = re.sub(r"^\[sudo\].*?password[^:]*:\s*", "", err, flags=re.I)
    err = re.sub(r"sudo: [^\n]*\n?", "", err)
    return out, err, rc


DEFAULT_BASES = ["/etc/ShellCrash", "/usr/share/ShellCrash", "/usr/local/ShellCrash",
                 "/opt/ShellCrash", "/root/ShellCrash", "/data/ShellCrash",
                 "/mnt/ShellCrash", "/jffs/ShellCrash"]
SAFE_BASE = re.compile(r"^/[A-Za-z0-9._/+@-]+$")


def _stamp():
    return time.strftime("%Y%m%d%H%M%S")


# 扫描候选目录：优先从运行中的 CrashCore 进程反推安装位置
SCAN_SH = r"""
echo "==exe=="
p=$(pidof CrashCore 2>/dev/null | cut -d" " -f1)
[ -z "$p" ] && p=$(pgrep -f CrashCore 2>/dev/null | head -n1)
if [ -n "$p" ]; then readlink /proc/$p/exe 2>/dev/null; fi
echo "==def=="
for d in /etc/ShellCrash /usr/share/ShellCrash /usr/local/ShellCrash /opt/ShellCrash /root/ShellCrash /data/ShellCrash /mnt/ShellCrash /jffs/ShellCrash; do
  [ -d "$d" ] && echo "$d"
done
echo "==find=="
find /etc /usr /opt /root /data /mnt /jffs /volume1 /volume2 -maxdepth 4 -type d -name "ShellCrash" 2>/dev/null | head -n 30
echo "==end=="
"""

# 给候选目录补齐详情（是否含 rules.yaml / ShellCrash.cfg / 版本号）
DETAIL_SH = r"""
for d in %s; do
  [ -d "$d" ] || continue
  r=0; c=0; v=-
  [ -f "$d/yamls/rules.yaml" ] && r=1
  if [ -f "$d/configs/ShellCrash.cfg" ]; then
    c=1
    v=$(sed -n "s/^version=//p" "$d/configs/ShellCrash.cfg" 2>/dev/null | head -n1)
  fi
  echo "$d|$r|$c|${v:--}"
done
"""

# 内核状态采集（busybox ps 不支持 -eo，这里直接读 /proc）
STATUS_SH = r"""
p=$(pidof CrashCore 2>/dev/null | cut -d" " -f1)
[ -z "$p" ] && p=$(pgrep -f CrashCore 2>/dev/null | head -n1)
echo "pid=$p"
if [ -n "$p" ] && [ -d "/proc/$p" ]; then
  echo "mem_kb=$(awk "/^VmRSS/{print \$2}" /proc/$p/status 2>/dev/null)"
  echo "uptime=$(awk "{print \$1}" /proc/uptime 2>/dev/null) $(awk "{print \$22}" /proc/$p/stat 2>/dev/null)"
  a=$(awk "{print \$14+\$15}" /proc/$p/stat 2>/dev/null)
  sleep 1
  b=$(awk "{print \$14+\$15}" /proc/$p/stat 2>/dev/null)
  echo "cpu_ticks=$((b-a))"
fi
echo "cfg_redir=$(sed -n "s/^redir_mod=//p" __BASE__/configs/ShellCrash.cfg 2>/dev/null | head -n1)"
echo "cfg_dns=$(sed -n "s/^dns_mod=//p" __BASE__/configs/ShellCrash.cfg 2>/dev/null | head -n1)"
echo "cfg_ver=$(sed -n "s/^version=//p" __BASE__/configs/ShellCrash.cfg 2>/dev/null | head -n1)"
echo "done=1"
"""

# 轻量信息采集（不含 sleep，连接时用）
INFO_SH = r"""
p=$(pidof CrashCore 2>/dev/null | cut -d" " -f1)
[ -z "$p" ] && p=$(pgrep -f CrashCore 2>/dev/null | head -n1)
echo "pid=$p"
echo "cfg_ver=$(sed -n "s/^version=//p" __BASE__/configs/ShellCrash.cfg 2>/dev/null | head -n1)"
echo "done=1"
"""

CTRL_SH = r"""
for f in /tmp/ShellCrash/config.yaml __BASE__/yamls/config.yaml; do
  if [ -f "$f" ]; then
    sed -n "s/^external-controller: *//p" "$f" 2>/dev/null | head -n1
    sed -n "s/^secret: *//p" "$f" 2>/dev/null | head -n1
    exit 0
  fi
done
"""


class Remote:
    # 远端只做「读文件 / 写文件 / 跑命令」，所有解析都在本地完成。
    def __init__(self, client, sudo_pwd=""):
        self.client = client
        self.sudo_pwd = sudo_pwd or ""
        self.sudo = None
        self._ctrl = None

    # ---------- 基础执行 ----------
    def sh(self, cmd, timeout=30):
        return run_cmd(self.client, cmd, timeout)

    def sudo_prefix(self):
        if self.sudo is None:
            try:
                out, _, _ = self.sh("id -u 2>/dev/null; command -v sudo 2>/dev/null", 8)
                lines = [x.strip() for x in out.splitlines() if x.strip()]
                uid = lines[0] if lines else ""
                has_sudo = any("sudo" in x for x in lines[1:])
                self.sudo = "" if (uid == "0" or not has_sudo) else "sudo"
            except Exception:
                self.sudo = ""
        return self.sudo

    def root(self, script, timeout=30):
        sudo = self.sudo_prefix()
        if not sudo:
            return self.sh("sh -c %s" % shlex.quote(script), timeout)
        return self.sh(
            "printf %%s %s | sudo -S -p '' sh -c %s" % (
                shlex.quote(self.sudo_pwd + "\n"), shlex.quote(script)),
            timeout)

    # ---------- 文件 ----------
    def read_text(self, path, timeout=25):
        out, err, rc = self.root("cat %s 2>/dev/null" % shlex.quote(path), timeout)
        return out

    def exists(self, path):
        out, _, _ = self.root("test -e %s && echo YES || echo NO" % shlex.quote(path), 12)
        return "YES" in out

    def write_text(self, path, text, backup=True, timeout=90):
        # 分字符（不是字节）切块，中文不会被切坏；重复上一条命令避免命令行过长
        if not text.endswith("\n"):
            text += "\n"
        raw_len = len(text.encode("utf-8"))
        tmp = path + ".tmp"
        q, qt = shlex.quote(path), shlex.quote(tmp)
        d = path.rsplit("/", 1)[0] or "/"
        bak = path + ".bak." + _stamp()

        prep = "mkdir -p %s 2>/dev/null; : > %s" % (shlex.quote(d), qt)
        if backup:
            prep += "; if [ -f %s ]; then cp -p %s %s 2>/dev/null || true; fi" % (
                q, q, shlex.quote(bak))
        out, err, rc = self.root(prep, 20)
        if rc != 0:
            raise RuntimeError("写入准备失败：%s" % ((err or out).strip()[:200]))

        parts = [text[i:i + 500] for i in range(0, len(text), 500)] or [""]
        batch, blen = [], 0

        def flush(items):
            o, e, r = self.root("; ".join(items), timeout)
            if r != 0:
                raise RuntimeError("写入失败：%s" % ((e or o).strip()[:200]))

        for p in parts:
            seg = "printf %%s %s >> %s" % (shlex.quote(p), qt)
            if batch and blen + len(seg) > 2400:
                flush(batch); batch, blen = [], 0
            batch.append(seg); blen += len(seg)
        if batch:
            flush(batch)

        out, err, rc = self.root("mv -f %s %s" % (qt, q), 20)
        if rc != 0:
            raise RuntimeError("保存失败：%s" % ((err or out).strip()[:200]))
        try:
            o, _, _ = self.root("wc -c < %s" % q, 15)
            got = int((o.strip().split() or ["0"])[0])
            if got != raw_len:
                raise RuntimeError("写入校验失败：期望 %d 字节，实际 %d 字节" % (raw_len, got))
        except ValueError:
            pass
        return bak if backup else ""

    # ---------- 外置控制器 ----------
    def ctrl(self, base, refresh=False):
        if self._ctrl is not None and not refresh:
            return self._ctrl
        host, port, secret = "127.0.0.1", 9090, ""
        try:
            script = CTRL_SH.replace("__BASE__", base)
            out, _, _ = self.root(script, 15)
            vals = [x.strip().strip("\"'") for x in out.splitlines() if x.strip()]
            if vals:
                v = vals[0]
                if v.startswith(":"):
                    v = "127.0.0.1" + v
                v = re.sub(r"^https?://", "", v)
                if "/" in v:
                    v = v.split("/", 1)[0]
                if ":" in v:
                    h, p = v.rsplit(":", 1)
                    host = h or "127.0.0.1"
                    port = int(p) if p.isdigit() else 9090
                elif v:
                    host = v
                if host in ("0.0.0.0", "::", "*"):
                    host = "127.0.0.1"
            if len(vals) > 1:
                secret = vals[1]
        except Exception:
            pass
        self._ctrl = (host, port, secret)
        return self._ctrl

    def ctrl_str(self, base):
        h, p, _ = self.ctrl(base)
        return "http://%s:%d" % (h, p)

    def http(self, base, path, method="GET", payload=None, timeout=15):
        host, port, secret = self.ctrl(base)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None

        def request_bytes():
            lines = ["%s %s HTTP/1.1" % (method, path),
                     "Host: %s:%d" % (host, port),
                     "Accept: application/json",
                     "User-Agent: SCRuleMgr",
                     "Connection: close"]
            if body is not None:
                lines.append("Content-Type: application/json")
                lines.append("Content-Length: %d" % len(body))
            if secret:
                lines.append("Authorization: Bearer " + secret)
            return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + (body or b"")

        # 1) 首选：SSH 直连隧道到控制器（不依赖远端 curl/wget）
        try:
            tr = self.client.get_transport()
            ch = tr.open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=timeout)
            try:
                ch.sendall(request_bytes())
                buf = b""
                deadline = time.time() + timeout
                while time.time() < deadline:
                    if ch.recv_ready():
                        d = ch.recv(65536)
                        if not d:
                            break
                        buf += d
                        he = buf.find(b"\r\n\r\n")
                        if he >= 0:
                            m = re.search(rb"Content-Length:\s*(\d+)", buf[:he], re.I)
                            if m and len(buf) - he - 4 >= int(m.group(1)):
                                break
                    elif ch.eof_received or ch.exit_status_ready():
                        break
                    else:
                        time.sleep(0.02)
            finally:
                try:
                    ch.close()
                except Exception:
                    pass
            return self._parse_http(buf)
        except Exception:
            pass
        # 2) 兜底：远端 curl / wget
        return self._http_remote(host, port, secret, path, method, body, timeout)

    @staticmethod
    def _parse_http(buf):
        if not buf:
            raise RuntimeError("外置控制器无响应（请确认内核在运行、端口正确）")
        he = buf.find(b"\r\n\r\n")
        if he < 0:
            raise RuntimeError("外置控制器响应不完整")
        head = buf[:he].decode("latin1")
        body = buf[he + 4:]
        first = head.split("\r\n")[0].split()
        code = int(first[1]) if len(first) > 1 and first[1].isdigit() else 0
        if re.search(r"Transfer-Encoding:\s*chunked", head, re.I):
            out, i = b"", 0
            while i < len(body):
                j = body.find(b"\r\n", i)
                if j < 0:
                    break
                try:
                    n = int(body[i:j].split(b";")[0].strip(), 16)
                except Exception:
                    break
                if n == 0:
                    break
                out += body[j + 2:j + 2 + n]
                i = j + 2 + n + 2
            body = out
        txt = body.decode("utf-8", "replace").strip()
        if code >= 400:
            raise RuntimeError("控制器返回 HTTP %d：%s" % (code, txt[:160]))
        return json.loads(txt) if txt[:1] in ("{", "[") else {}

    def _http_remote(self, host, port, secret, path, method, body, timeout):
        url = "http://%s:%d%s" % (host, port, path)
        if method == "GET":
            script = ("(curl -s --max-time %d %s 2>/dev/null || wget -q -O - --timeout=%d %s 2>/dev/null)"
                      % (timeout, shlex.quote(url), timeout, shlex.quote(url)))
        else:
            payload = (body or b"").decode("utf-8", "replace")
            script = ("printf %%s %s > /tmp/sc_body.json; "
                      "curl -s -X %s --max-time %d --data-binary @/tmp/sc_body.json "
                      "-H 'Content-Type: application/json' %s"
                      % (shlex.quote(payload), method, timeout, shlex.quote(url)))
        out, err, rc = self.root(script, timeout + 10)
        txt = out.strip()
        if not txt:
            raise RuntimeError("控制器无响应：%s" % ((err or "远端无 curl/wget").strip()[:160]))
        return json.loads(txt) if txt[:1] in ("{", "[") else {}


# ============================================================
# 扫描与目录选择
# ============================================================
def scan_bases(R, prefer=""):
    try:
        out, _, _ = R.root(SCAN_SH, 70)
    except Exception:
        out = ""
    sec, exe, defs, found = None, [], [], []
    for ln in out.splitlines():
        t = ln.strip()
        if not t:
            continue
        m = re.match(r"^==(\w+)==$", t)
        if m:
            sec = m.group(1)
            continue
        if sec == "exe" and t.startswith("/"):
            d = t.rsplit("/", 1)[0]
            exe.append(d)
            # 内核若在 <安装目录>/bin/ 下，再上跳一层
            if d.rsplit("/", 1)[-1] in ("bin", "core", "tools", "libs"):
                exe.append(d.rsplit("/", 1)[0])
        elif sec == "def":
            defs.append(t)
        elif sec == "find":
            found.append(t)

    ordered, seen = [], set()
    for c in (exe + defs + found + ([prefer] if prefer else [])):
        c = (c or "").strip().rstrip("/")
        if not c or c in seen or not SAFE_BASE.match(c):
            continue
        seen.add(c)
        ordered.append(c)

    details = []
    if ordered:
        script = DETAIL_SH % " ".join(shlex.quote(c) for c in ordered)
        try:
            dout, _, _ = R.root(script, 45)
        except Exception:
            dout = ""
        dmap = {}
        for ln in dout.splitlines():
            p = ln.strip().split("|")
            if len(p) >= 4:
                dmap[p[0]] = {"rules": p[1] == "1", "cfg": p[2] == "1", "version": p[3] or "-"}
        for c in ordered:
            i = dmap.get(c) or {"rules": False, "cfg": False, "version": "-"}
            details.append({"path": c, "valid": bool(i["rules"] or i["cfg"]),
                            "version": i["version"], "has_rules": i["rules"],
                            "has_cfg": i["cfg"]})
    details.sort(key=lambda x: (not x["valid"],))
    return details


def pick_base(details, prefer=""):
    pref = (prefer or "").strip().rstrip("/")
    if pref:
        for d in details:
            if d["path"] == pref and d["valid"]:
                return d["path"]
    for d in details:
        if d["valid"]:
            return d["path"]
    if pref:
        return pref
    return details[0]["path"] if details else ""


# ============================================================
# 业务操作（全部在本地完成，远端只读写文件）
# ============================================================
def _rp(base):
    return (base or "/etc/ShellCrash") + "/yamls/rules.yaml"


def _cp(base):
    return (base or "/etc/ShellCrash") + "/yamls/proxy-groups.yaml"


CG_HEAD = "#用于添加自定义策略组"


def _cg_norm(text):
    body = [l for l in text.replace("\r", "").split("\n")
            if l.strip() and not l.strip().startswith("#")]
    out = CG_HEAD + "\n" + "\n".join(body)
    return out if out.endswith("\n") else out + "\n"


def _cg_names(text):
    names = []
    for l in (text or "").split("\n"):
        t = l.strip()
        if t.startswith("- name:"):
            nm = t.split(":", 1)[1].strip().rstrip(",").strip("'\"")
            if nm:
                names.append(nm)
    return names


def op_scan(R, base, a):
    prefer = (a.get("base") or "").strip() or base
    details = scan_bases(R, prefer)
    return {"ok": True, "candidates": details, "current": base,
            "count": len(details), "valid": len([d for d in details if d["valid"]])}


def op_groups(R, base, a):
    d = R.http(base, "/proxies")
    groups = []
    for name, v in (d.get("proxies") or {}).items():
        if v.get("type") in ("Selector", "Fallback", "URLTest"):
            groups.append({"name": name, "type": v.get("type"),
                           "now": v.get("now"), "all": v.get("all") or []})
    groups.sort(key=lambda x: x["name"])
    return {"ok": True, "groups": groups, "controller": R.ctrl_str(base),
            "count": len(groups)}


def op_switch(R, base, a):
    name = a.get("name", "")
    target = a.get("target", "")
    enc = urllib.parse.quote(name, safe="")
    R.http(base, "/proxies/" + enc, "PUT", {"name": target})
    d = R.http(base, "/proxies/" + enc)
    return {"ok": True, "name": name, "now": d.get("now")}


def op_rules(R, base, a):
    return {"ok": True, "text": R.read_text(_rp(base)), "path": _rp(base)}


def op_set(R, base, a):
    text = a.get("text", "")
    if not text.endswith("\n"):
        text += "\n"
    bak = R.write_text(_rp(base), text)
    return {"ok": True, "backup": bak, "lines": len(text.splitlines())}


def op_add(R, base, a):
    typ = (a.get("type") or "DOMAIN-SUFFIX").strip()
    val = (a.get("value") or "").strip()
    grp = (a.get("group") or "DIRECT").strip()
    note = (a.get("note") or "").strip()
    if not val:
        return {"ok": False, "error": "规则值不能为空"}
    if any("\n" in x for x in (typ, val, grp)) or "," in typ:
        return {"ok": False, "error": "规则内容不合法（不能含换行，类型不能含逗号）"}
    line = "- %s,%s,%s" % (typ, val, grp)
    block = ("# " + note.replace("\n", " ") + "\n" if note else "") + line + "\n\n"
    old = R.read_text(_rp(base))
    bak = R.write_text(_rp(base), block + old)
    return {"ok": True, "rule": line, "backup": bak}


def op_delete(R, base, a):
    try:
        idx = int(a.get("line"))
    except Exception:
        return {"ok": False, "error": "行号不合法"}
    lines = R.read_text(_rp(base)).split("\n")
    if idx < 1 or idx > len(lines):
        return {"ok": False, "error": "行号超出范围"}
    removed = lines[idx - 1]
    start = idx - 1
    if start > 0 and lines[start - 1].strip().startswith("#") \
            and "====" not in lines[start - 1]:
        start -= 1
    del lines[start:idx]
    # 顺手收掉删除后留下的多余空行，保持文件行数与添加前一致
    if start < len(lines) and not lines[start].strip():
        prev_blank = (start == 0) or (not lines[start - 1].strip())
        if prev_blank and start + 1 < len(lines):
            del lines[start]
    R.write_text(_rp(base), "\n".join(lines))
    return {"ok": True, "removed": removed}


def op_cgroups(R, base, a):
    text = R.read_text(_cp(base))
    return {"ok": True, "text": text, "path": _cp(base),
            "names": _cg_names(text), "exists": bool(text.strip())}


def op_cgroup_set(R, base, a):
    bak = R.write_text(_cp(base), _cg_norm(a.get("text", "")))
    return {"ok": True, "backup": bak, "names": _cg_names(a.get("text", "")),
            "hint": "已保存，需重启内核生效"}


def op_cgroup_add(R, base, a):
    name = (a.get("name") or "").strip().strip("'\"")
    typ = (a.get("type") or "select").strip()
    if typ not in ("select", "url-test", "fallback", "load-balance"):
        return {"ok": False, "error": "策略组类型不合法"}
    if not name or "\n" in name or ":" in name or "#" in name:
        return {"ok": False, "error": "策略组名称不合法（不能为空或含冒号、#、换行）"}
    proxies = a.get("proxies") or []
    if isinstance(proxies, str):
        proxies = [p.strip() for p in proxies.split(",") if p.strip()]
    proxies = [str(p).strip() for p in proxies if str(p).strip()] or ["DIRECT"]
    for p in proxies:
        if "\n" in p or "#" in p:
            return {"ok": False, "error": "成员名不能含 # 或换行"}
    text = R.read_text(_cp(base))
    if name in _cg_names(text):
        return {"ok": False, "error": "策略组「%s」已存在" % name}
    block = "  - name: %s\n    type: %s\n" % (name, typ)
    if typ in ("url-test", "fallback", "load-balance"):
        url = (a.get("url") or "").strip() or "https://www.gstatic.com/generate_204"
        block += "    url: '%s'\n    interval: %s\n" % (url.replace("'", ""), int(a.get("interval") or 300))
    block += "    proxies:\n" + "".join("      - %s\n" % p for p in proxies)
    body = [l for l in text.replace("\r", "").split("\n")
            if l.strip() and not l.strip().startswith("#")]
    bak = R.write_text(_cp(base), _cg_norm("\n".join(body) + "\n" + block))
    return {"ok": True, "name": name, "backup": bak, "hint": "已写入 proxy-groups.yaml，需重启内核生效"}


def op_cgroup_delete(R, base, a):
    name = (a.get("name") or "").strip()
    text = R.read_text(_cp(base))
    if name not in _cg_names(text):
        return {"ok": False, "error": "未找到策略组「%s」" % name}
    lines = text.replace("\r", "").split("\n")
    out, i, n = [], 0, len(lines)
    while i < n:
        t = lines[i].strip()
        if t.startswith("- name:"):
            nm = t.split(":", 1)[1].strip().rstrip(",").strip("'\"")
            if nm == name:
                i += 1
                while i < n and not lines[i].strip().startswith("- name:"):
                    i += 1
                continue
        out.append(lines[i]); i += 1
    R.write_text(_cp(base), "\n".join(out))
    return {"ok": True, "name": name, "hint": "已删除，需重启内核生效"}


def op_allproxies(R, base, a):
    names = ["DIRECT", "REJECT"]
    try:
        d = R.http(base, "/proxies")
        names.extend(list((d.get("proxies") or {}).keys()))
    except Exception:
        pass
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n); out.append(n)
    return {"ok": True, "proxies": out}


def op_info(R, base, a):
    out, _, _ = R.root(INFO_SH.replace("__BASE__", base), 20)
    kv = {}
    for ln in out.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            kv[k.strip()] = v.strip()
    ver = (kv.get("cfg_ver") or "").strip()
    if not ver or ver == "-":
        # 有些版本 ShellCrash.cfg 里不写版本号，退回内核 /version
        try:
            ver = R.http(base, "/version").get("version") or ""
        except Exception:
            ver = ""
    return {"ok": True, "version": ver or "unknown",
            "core_active": bool(kv.get("pid")), "controller": R.ctrl_str(base),
            "base": base}


def _fmt_uptime(sec):
    try:
        sec = int(sec)
    except Exception:
        return ""
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return "%d天%d小时%d分" % (d, h, m)
    if h:
        return "%d小时%d分" % (h, m)
    if m:
        return "%d分%d秒" % (m, s)
    return "%d秒" % s


def op_status(R, base, a):
    st = {"ok": True, "running": False, "version": "", "meta": False, "uptime": "",
          "mem_mb": 0, "cpu": "", "pid": "", "mode": "", "log_level": "",
          "ports": {}, "tun": "", "conns": 0, "up_total": 0, "down_total": 0,
          "redir_mod": "", "dns_mod": "", "controller": R.ctrl_str(base), "base": base}
    try:
        out, _, _ = R.root(STATUS_SH.replace("__BASE__", base), 30)
        kv = {}
        for ln in out.splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                kv[k.strip()] = v.strip()
        st["pid"] = kv.get("pid") or ""
        st["running"] = bool(st["pid"])
        st["redir_mod"] = kv.get("cfg_redir") or ""
        st["dns_mod"] = kv.get("cfg_dns") or ""
        st["version"] = kv.get("cfg_ver") or ""
        try:
            st["mem_mb"] = round(int(kv.get("mem_kb") or 0) / 1024.0, 1)
        except Exception:
            pass
        parts = (kv.get("uptime") or "").split()
        if len(parts) == 2:
            try:
                st["uptime"] = _fmt_uptime(float(parts[0]) - float(parts[1]) / 100.0)
            except Exception:
                pass
        ticks = kv.get("cpu_ticks")
        if ticks is not None:
            try:
                st["cpu"] = "%d%%" % max(0, int(ticks))
            except Exception:
                pass
    except Exception:
        pass

    try:
        v = R.http(base, "/version")
        st["version"] = v.get("version") or st["version"]
        st["meta"] = bool(v.get("meta"))
    except Exception:
        pass
    try:
        c = R.http(base, "/configs")
        st["mode"] = c.get("mode", "")
        st["log_level"] = c.get("log-level", "")
        st["ports"] = {"mixed": c.get("mixed-port"), "redir": c.get("redir-port"),
                       "tproxy": c.get("tproxy-port"), "socks": c.get("socks-port"),
                       "http": c.get("port")}
        tun = c.get("tun") or {}
        st["tun"] = ("开启(%s)" % tun.get("device")) if tun.get("enable") else "关闭"
    except Exception:
        pass
    try:
        conn = R.http(base, "/connections")
        st["up_total"] = conn.get("uploadTotal", 0) or 0
        st["down_total"] = conn.get("downloadTotal", 0) or 0
        st["conns"] = len(conn.get("connections") or [])
    except Exception:
        pass
    return st


def op_restart(R, base, a):
    out, err, rc = R.root("sh %s 2>&1" % shlex.quote((base or "/etc/ShellCrash") + "/start.sh restart"), 110)
    return {"ok": rc == 0, "out": (out or "")[-600:], "err": (err or "")[-600:]}


OPS_CLIENT = {"scan": op_scan, "groups": op_groups, "switch": op_switch,
              "rules": op_rules, "set": op_set, "add": op_add, "delete": op_delete,
              "cgroups": op_cgroups, "cgroup_add": op_cgroup_add,
              "cgroup_delete": op_cgroup_delete, "cgroup_set": op_cgroup_set,
              "allproxies": op_allproxies, "status": op_status,
              "restart": op_restart, "info": op_info}


def agent_call(op, timeout=40, **kw):
    with SESS_LOCK:
        R = SESS.get("remote")
        base = SESS.get("base") or ""
    if R is None:
        return {"ok": False, "error": "尚未连接设备"}
    fn = OPS_CLIENT.get(op)
    if fn is None:
        return {"ok": False, "error": "未知操作：%s" % op}
    try:
        return fn(R, base, kw)
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}


# ============================================================
# HTTP 服务
# ============================================================
class Handler(BaseHTTPRequestHandler):
    server_version = "SCRuleMgr/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _auth(self):
        return self.headers.get("X-Token") == TOKEN

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
        except Exception:
            return {}

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            html = (PAGE.replace("__APP_NAME__", APP_NAME)
                        .replace("__VERSION__", VERSION)
                        .replace("__TOKEN__", TOKEN))
            return self._send(200, html, "text/html; charset=utf-8")
        if self.path.startswith("/api/ping"):
            STATE["last_ping"] = time.time()
            STATE["page_closed"] = None  # 有新心跳=页面仍在，撤销待执行的关闭
            with SESS_LOCK:
                conn = bool(SESS.get("connected"))
            return self._send(200, {"app": APP_NAME, "version": VERSION,
                                    "port": STATE.get("port"), "connected": conn})
        if self.path.startswith("/api/bye"):
            # 页面关闭信号。无需鉴权（sendBeacon 不能带自定义 header）。
            # 只记录时间，由 watchdog 延迟退出；若期间新页面 ping 则撤销。
            if STATE.get("page_closed") is None:
                STATE["page_closed"] = time.time()
            return self._send(200, {"ok": True})
        if not self._auth():
            return self._send(403, {"error": "无权限"})
        if self.path.startswith("/api/state"):
            saved = cfg_load()
            saved.pop("pwd_enc", None)
            return self._send(200, {
                "cfg": saved,
                "pwd": pwd_open(cfg_load().get("pwd_enc", "")),
                "connected": SESS.get("connected", False),
                "base": SESS.get("base", ""),
                "version": VERSION,
            })
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        # 前端 sendBeacon('/api/bye') 发出的是 POST，且不能带自定义 header。
        # 必须放在鉴权之前处理，否则会返回 403，导致 page_closed 永不置位。
        if self.path.startswith("/api/bye"):
            if STATE.get("page_closed") is None:
                STATE["page_closed"] = time.time()
            return self._send(200, {"ok": True})
        if not self._auth():
            return self._send(403, {"error": "无权限"})
        body = self._body()
        p = self.path

        if p.startswith("/api/connect"):
            host = (body.get("host") or "").strip()
            user = (body.get("user") or "").strip()
            pwd = body.get("pwd") or ""
            sudo_pwd = body.get("sudo_pwd") or pwd
            if not host or not user:
                return self._send(400, {"error": "请填写 NAS 地址和用户名（免密登录可留空密码）"})
            with SESS_LOCK:
                old = SESS.get("client")
                if old:
                    try:
                        old.close()
                    except Exception:
                        pass
                SESS["connected"] = False
            try:
                client = ssh_connect(host, user, pwd)
                # 只有勾了「记住」才保存用户名和密码；否则清掉上次残留，免得下次打开又被自动填上
                if body.get("remember"):
                    cfg_save({"host": host, "user": user, "sudo_pwd": sudo_pwd})
                    cfg_remember(pwd, True)
                else:
                    cfg_save({"host": host})
                    cfg_drop("user", "sudo_pwd")
                    cfg_remember("", False)
                R = Remote(client, sudo_pwd)
                with SESS_LOCK:
                    SESS["client"] = client
                    SESS["remote"] = R
                    SESS["cfg"] = {"host": host, "user": user,
                                   "pwd": pwd, "sudo_pwd": sudo_pwd}
                prefer = (body.get("base") or "").strip() or (cfg_load().get("base") or "")
                details = scan_bases(R, prefer)
                pick = pick_base(details, prefer)
                with SESS_LOCK:
                    SESS["base"] = pick
                cfg_save({"base": pick})
                info = agent_call("info", timeout=30)
                groups = agent_call("groups", timeout=30)
                rules = agent_call("rules", timeout=30)
                with SESS_LOCK:
                    SESS["connected"] = True
                return self._send(200, {"ok": True, "info": info, "groups": groups,
                                        "rules": rules, "base": pick,
                                        "candidates": details})
            except Exception as e:
                return self._send(200, {"ok": False, "error": friendly_error(e)})

        if p.startswith("/api/disconnect"):
            with SESS_LOCK:
                c = SESS.get("client")
                if c:
                    try:
                        c.close()
                    except Exception:
                        pass
                SESS["client"] = None
                SESS["remote"] = None
                SESS["connected"] = False
            return self._send(200, {"ok": True})

        if p.startswith("/api/scan"):
            return self._send(200, agent_call("scan", timeout=90))

        if p.startswith("/api/base"):
            nb = (body.get("base") or "").strip().rstrip("/")
            if not nb or not SAFE_BASE.match(nb):
                return self._send(400, {"error": "目录不合法"})
            with SESS_LOCK:
                R = SESS.get("remote")
                if R is None:
                    return self._send(400, {"error": "尚未连接设备"})
                SESS["base"] = nb
                R._ctrl = None
            cfg_save({"base": nb})
            return self._send(200, {"ok": True, "base": nb})

        if p.startswith("/api/groups"):
            return self._send(200, agent_call("groups", timeout=20))

        if p.startswith("/api/switch"):
            name = body.get("name", "")
            target = body.get("target", "")
            if not name or not target:
                return self._send(400, {"error": "缺少策略组或选项"})
            return self._send(200, agent_call("switch", timeout=20,
                                              name=name, target=target))

        if p.startswith("/api/rules"):
            return self._send(200, agent_call("rules", timeout=20))

        if p.startswith("/api/rule/add"):
            return self._send(200, agent_call("add", timeout=20,
                                              type=body.get("type", "DOMAIN-SUFFIX"),
                                              value=body.get("value", ""),
                                              group=body.get("group", "DIRECT"),
                                              note=body.get("note", "")))

        if p.startswith("/api/rule/delete"):
            return self._send(200, agent_call("delete", timeout=20,
                                              line=body.get("line")))

        if p.startswith("/api/rule/set"):
            return self._send(200, agent_call("set", timeout=20,
                                              text=body.get("text", "")))

        if p.startswith("/api/cgroups"):
            return self._send(200, agent_call("cgroups", timeout=20))

        if p.startswith("/api/allproxies"):
            return self._send(200, agent_call("allproxies", timeout=20))

        if p.startswith("/api/status"):
            return self._send(200, agent_call("status", timeout=25))

        if p.startswith("/api/cgroup/add"):
            return self._send(200, agent_call("cgroup_add", timeout=20,
                                              name=body.get("name", ""),
                                              type=body.get("type", "select"),
                                              proxies=body.get("proxies", []),
                                              url=body.get("url", ""),
                                              interval=body.get("interval", 300)))

        if p.startswith("/api/cgroup/delete"):
            return self._send(200, agent_call("cgroup_delete", timeout=20,
                                              name=body.get("name", "")))

        if p.startswith("/api/cgroup/set"):
            return self._send(200, agent_call("cgroup_set", timeout=20,
                                              text=body.get("text", "")))

        if p.startswith("/api/restart"):
            with SESS_LOCK:
                SESS["busy"] = True
            try:
                res = agent_call("restart", timeout=110)
                return self._send(200, res)
            finally:
                with SESS_LOCK:
                    SESS["busy"] = False

        if p.startswith("/api/exit"):
            if any_run_active():
                return self._send(409, {"error": "还有任务在执行，稍后再试"})
            self._send(200, {"ok": True})
            shutdown_app(0.6)
            return

        return self._send(404, {"error": "not found"})


def serve(port, open_browser=True):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    STATE["httpd"] = httpd
    STATE["port"] = port
    STATE["last_ping"] = time.time()
    STATE["page_closed"] = None
    url = "http://127.0.0.1:%d/" % port
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    threading.Thread(target=watchdog, daemon=True).start()
    print("%s v%s 已启动：%s" % (APP_NAME, VERSION, url))
    httpd.serve_forever()


def find_running(port=PORT_BASE, tries=10):
    for p in range(port, port + tries):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/api/ping" % p, timeout=1.0) as r:
                j = json.loads(r.read().decode("utf-8"))
            if j.get("app") == APP_NAME:
                return p, True
        except urllib.error.HTTPError:
            return p, False
        except Exception:
            continue
    return None, None


def cli():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=PORT_BASE)
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()
    return serve(a.port, open_browser=not a.no_open)


def main():
    if len(sys.argv) > 1:
        return cli()
    port = PORT_BASE
    old, ours = find_running(port)
    if old and ours:
        webbrowser.open("http://127.0.0.1:%d/" % old)
        return
    if old and not ours:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0, "检测到占用端口 %d 的旧实例，请先在任务管理器结束它。" % old,
                APP_NAME, 0x40)
        except Exception:
            pass
        return
    for i in range(20):
        try:
            return serve(port + i)
        except OSError:
            continue
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, "端口均被占用，无法启动。", APP_NAME, 0x10)
    except Exception:
        pass


# ============================================================
# 前端页面
# ============================================================
PAGE = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__APP_NAME__</title>
<style>
:root{
  --bg:#f5f7fa; --card:#fff; --ink:#1f2937; --muted:#6b7280;
  --line:#e5e7eb; --brand:#2563eb; --brand2:#1d4ed8;
  --ok:#059669; --warn:#d97706; --err:#dc2626; --soft:#eff6ff;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:22px 18px 60px}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
h1{font-size:20px;margin:0;font-weight:650}
h1 small{font-size:12px;color:var(--muted);font-weight:400;margin-left:8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
  padding:18px 20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.card h2{font-size:15px;margin:0 0 14px;font-weight:600;display:flex;align-items:center;gap:8px}
.card h2 .n{display:inline-flex;width:20px;height:20px;border-radius:6px;background:var(--brand);
  color:#fff;align-items:center;justify-content:center;font-size:12px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
label{font-size:13px;color:var(--muted)}
input,select,textarea{font:inherit;color:var(--ink);border:1px solid var(--line);
  border-radius:7px;padding:7px 10px;background:#fff;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--brand);box-shadow:0 0 0 3px rgba(37,99,235,.12)}
input[type=text]{min-width:150px}
.f1{flex:1}
button{font:inherit;border:0;border-radius:7px;padding:8px 15px;cursor:pointer;
  background:var(--brand);color:#fff;font-weight:500;transition:.15s}
button:hover{background:var(--brand2)}
button.ghost{background:#eef2f7;color:var(--ink)}
button.ghost:hover{background:#e2e8f0}
button.sm{padding:4px 10px;font-size:12px}
button.danger{background:#fee;color:var(--err)}
button.danger:hover{background:#fdd}
button:disabled{opacity:.5;cursor:not-allowed}
.chk{display:flex;align-items:center;gap:5px;font-size:13px;color:var(--muted)}
.muted{color:var(--muted);font-size:12px}
.msg{margin-top:10px;padding:9px 12px;border-radius:7px;font-size:13px;display:none}
.msg.show{display:block}
.msg.err{background:#fef2f2;color:var(--err)}
.msg.ok{background:#ecfdf5;color:var(--ok)}
.msg.warn{background:#fffbeb;color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--muted);font-weight:500;font-size:12px;background:#fafbfc}
tr:hover td{background:#fafbff}
.tag{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;background:#eef2f7;color:#475569}
.tag.select{background:#dbeafe;color:#1d4ed8}
.tag.urltest{background:#dcfce7;color:#15803d}
.now{font-weight:600;color:var(--brand)}
.scroll{max-height:420px;overflow:auto;border:1px solid var(--line);border-radius:8px}
textarea{width:100%;min-height:200px;font:12px/1.55 ui-monospace,Consolas,monospace;resize:vertical}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:820px){.two{grid-template-columns:1fr}}
.hidden{display:none}
.badge{padding:3px 9px;border-radius:20px;font-size:12px;font-weight:500}
.badge.on{background:#dcfce7;color:#15803d}
.badge.off{background:#fee2e2;color:#dc2626}
hr{border:0;border-top:1px solid var(--line);margin:16px 0}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.stat{background:#f8fafc;border:1px solid var(--line);border-radius:9px;padding:10px 12px}
.stat .k{font-size:11px;color:var(--muted);margin-bottom:3px}
.stat .v{font-size:15px;font-weight:600;color:var(--ink);word-break:break-all}
.stat .v small{font-size:11px;font-weight:400;color:var(--muted)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot.on{background:#10b981;box-shadow:0 0 0 3px rgba(16,185,129,.15)}
.dot.off{background:#ef4444;box-shadow:0 0 0 3px rgba(239,68,68,.15)}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>__APP_NAME__ <small>v__VERSION__ · 策略组与自定义规则</small></h1>
  <div class="row">
    <span id="connBadge" class="badge off">未连接</span>
    <button class="ghost sm" onclick="doExit()">退出程序</button>
  </div>
</header>

<div class="card" id="connCard">
  <h2><span class="n">1</span>连接设备（飞牛 NAS / OpenWrt）</h2>
  <div class="row">
    <label>IP</label><input type="text" id="host" placeholder="192.168.1.100">
    <label>用户名</label><input type="text" id="user" placeholder="如 root">
    <label>密码</label><input type="password" id="pwd" autocomplete="current-password">
    <label class="chk" title="勾选后下次打开自动填入用户名和密码；不勾则不保存"><input type="checkbox" id="remember"> 记住</label>
    <button id="btnConn" onclick="doConnect()">连接</button>
    <button class="ghost" id="btnDisc" onclick="doDisconnect()" style="display:none">断开</button>
  </div>
  <div class="msg" id="connMsg"></div>
  <div class="muted" style="margin-top:8px">未勾选「记住」时不会保存用户名和密码，下次打开是空白。</div>
  <div class="muted" style="margin-top:8px">sudo 密码默认与登录密码相同；如不同请在这里填写：</div>
  <div class="row" style="margin-top:6px"><input type="password" id="sudoPwd" placeholder="留空 = 同登录密码" style="max-width:220px"></div>
</div>

<div id="main" class="hidden">
  <div class="card" id="baseCard">
    <h2><span class="n">2</span>ShellCrash 安装目录
      <button class="ghost sm" style="margin-left:auto" onclick="scanBase(true)">重新扫描</button>
    </h2>
    <div class="muted" style="margin-bottom:10px">
      自动识别设备上 ShellCrash 的安装位置（常见为 <code>/etc/ShellCrash</code>）。识别不准可手动切换。
    </div>
    <div class="row">
      <span class="muted">当前使用</span>
      <code id="baseNow">—</code>
      <select id="basePick" class="f1" style="max-width:420px"></select>
      <button onclick="applyBase()">切换到该目录</button>
    </div>
    <div class="msg" id="baseMsg"></div>
  </div>

  <div class="card" id="infoCard">
    <h2><span class="n">3</span>内核当前状态
      <button class="ghost sm" style="margin-left:auto" onclick="loadStatus()">刷新</button>
    </h2>
    <div class="stat-grid" id="statGrid">
      <div class="muted">读取中…</div>
    </div>
    <div class="muted" id="infoLine" style="margin-top:10px"></div>
  </div>

  <div class="card">
    <h2><span class="n">4</span>自定义策略组（yamls/proxy-groups.yaml）</h2>
    <div class="muted" style="margin-bottom:10px">
      新建的策略组写入 <code>proxy-groups.yaml</code>，重启内核后自动合并生效（订阅更新不会冲掉）。
      成员可以是节点名或已有策略组名，可下拉选也可手填。
    </div>
    <div class="two">
      <div>
        <label>现有自定义策略组</label>
        <div class="scroll" style="max-height:180px;margin-top:6px"><table>
          <thead><tr><th>名称</th><th>类型</th><th style="width:56px"></th></tr></thead>
          <tbody id="cgroupBody"></tbody>
        </table></div>
        <div class="row" style="margin-top:8px">
          <button class="ghost sm" onclick="loadCgroups()">刷新列表</button>
        </div>
      </div>
      <div>
        <label>新建策略组</label>
        <div class="row" style="margin-top:6px">
          <input type="text" id="cgName" class="f1" placeholder="组名，如 🏠 家庭自建">
          <select id="cgType" onchange="toggleCgUrl()">
            <option value="select">select（手动选择）</option>
            <option value="url-test">url-test（测速）</option>
            <option value="fallback">fallback（故障转移）</option>
            <option value="load-balance">load-balance（负载均衡）</option>
          </select>
        </div>
        <div class="row" id="cgUrlRow" style="margin-top:6px;display:none">
          <input type="text" id="cgUrl" class="f1" placeholder="测速地址（留空用 gstatic）">
          <input type="number" id="cgInterval" value="300" style="width:90px" title="检测间隔(秒)">
        </div>
        <div style="margin-top:6px">
          <label>成员（下拉选择加入，可手填逗号分隔）</label>
          <div class="row" style="margin-top:6px">
            <select id="cgMemberPick" class="f1"><option value="">加载节点中…</option></select>
            <button class="ghost sm" onclick="addCgMember()">加入</button>
            <button class="ghost sm" onclick="loadAllProxies()">刷新节点</button>
          </div>
          <input type="text" id="cgMembers" class="f1" style="margin-top:6px;width:100%"
                 placeholder="成员，逗号分隔，如 香港01,美国Y02,DIRECT">
        </div>
        <div class="row" style="margin-top:8px">
          <button onclick="addCgroup()">新建策略组</button>
        </div>
      </div>
    </div>
    <hr>
    <label>直接编辑整个文件（高级）</label>
    <textarea id="cgText" spellcheck="false" style="min-height:120px"></textarea>
    <div class="row" style="margin-top:10px">
      <button class="ghost" onclick="loadCgroups()">重新读取</button>
      <button class="ghost" onclick="saveCgText()">保存文本改动</button>
      <button onclick="restartForGroups()">重启内核使策略组生效</button>
    </div>
    <div class="msg" id="cgMsg"></div>
  </div>

  <div class="card">
    <h2><span class="n">5</span>自定义规则（yamls/rules.yaml）</h2>
    <div class="muted" style="margin-bottom:10px">
      这些规则排在规则表最前面，优先匹配。改动会先自动备份，但<b>必须重启内核才生效</b>。
    </div>
    <div class="two">
      <div>
        <label>快速添加一条规则</label>
        <div class="row" style="margin-top:6px">
          <select id="rType">
            <option>DOMAIN-SUFFIX</option><option>DOMAIN</option>
            <option>DOMAIN-KEYWORD</option><option>IP-CIDR</option>
            <option>GEOSITE</option><option>GEOIP</option>
          </select>
          <input type="text" id="rValue" class="f1" placeholder="mclick.simba.taobao.com">
        </div>
        <div class="row" style="margin-top:6px">
          <label>策略组</label>
          <input type="text" id="rGroup" class="f1" list="groupList" autocomplete="off" placeholder="可直接输入或下拉选择">
          <datalist id="groupList"></datalist>
          <button class="ghost sm" onclick="loadGroups(true)" title="从 NAS 重新读取策略组列表">刷新</button>
        </div>
        <div class="row" style="margin-top:6px">
          <input type="text" id="rNote" class="f1" placeholder="备注（可选）">
          <button onclick="addRule()">添加</button>
        </div>
        <div class="row" style="margin-top:10px">
          <button class="ghost sm" onclick="quickAdd('DIRECT')">放行到 DIRECT</button>
          <button class="ghost sm" onclick="quickAdd('🎯 全球直连')">放行到直连组</button>
          <button class="ghost sm" onclick="quickAdd('REJECT')">加入拦截</button>
        </div>
      </div>
      <div>
        <label>规则列表（按行号删除）</label>
        <div class="scroll" style="max-height:230px;margin-top:6px"><table>
          <thead><tr><th style="width:46px">行</th><th>规则</th><th style="width:56px"></th></tr></thead>
          <tbody id="ruleBody"></tbody>
        </table></div>
      </div>
    </div>
    <hr>
    <label>直接编辑整个文件（高级）</label>
    <textarea id="ruleText" spellcheck="false"></textarea>
    <div class="row" style="margin-top:10px">
      <button class="ghost" onclick="loadRules()">重新读取</button>
      <button class="ghost" onclick="saveRules()">保存文本改动</button>
      <button onclick="doRestart()" id="btnRestart">重启内核使规则生效</button>
    </div>
    <div class="msg" id="ruleMsg"></div>
  </div>
</div>

<div class="muted" style="text-align:center;margin-top:20px">
  关闭本网页即自动退出程序，无需手动结束进程 · 远端只执行 shell 命令，不需要安装 python3
</div>
</div>

<script>
const TOKEN='__TOKEN__';
const $=id=>document.getElementById(id);
let GROUPS=[], ALLGROUPS=[], ALLPROXIES=[];
function svcLost(on){
  let b=document.getElementById('svcLost');
  if(on){
    if(b)return;
    b=document.createElement('div');b.id='svcLost';
    b.style.cssText='position:fixed;left:0;right:0;top:0;z-index:9999;background:#b91c1c;color:#fff;padding:11px 18px;font-size:14px;text-align:center;box-shadow:0 2px 10px rgba(0,0,0,.25)';
    b.innerHTML='后台服务已退出，当前操作未完成。请重新双击「ShellCrash规则管理器.exe」，页面会自动恢复。';
    document.body.insertBefore(b,document.body.firstChild);
  }else if(b){b.remove()}
}
async function api(path,body){
  // 后端只有 /api/state 用 GET，其余业务接口(/api/groups、/api/rules 等)均为 POST。
  // 无参数调用也必须发 POST + 空 JSON，否则会命中 do_GET 的 404 → "not found"。
  const isGet=(path==='/api/state');
  const opt={method:isGet?'GET':'POST',headers:{'X-Token':TOKEN}};
  if(!isGet){opt.headers['Content-Type']='application/json';opt.body=JSON.stringify(body||{})}
  let r;
  try{
    r=await fetch(path,opt);
    svcLost(false);
  }catch(e){
    svcLost(true);
    throw new Error('后台服务未响应');
  }
  return await r.json();
}
function show(id,msg,type){const e=$(id);e.textContent=msg;e.className='msg show '+type}
function hide(id){$(id).className='msg'}

(async function init(){
  try{
    const s=await api('/api/state');
    const c=s.cfg||{};
    $('host').value=c.host||'192.168.1.100';
    $('user').value=c.user||'';
    $('sudoPwd').value=c.sudo_pwd||'';
    if(s.pwd){$('pwd').value=s.pwd;$('remember').checked=true}
    if(s.connected){setConnected(true);$('baseNow').textContent=s.base||'—';await loadAll();try{await scanBase(false)}catch(e){}}
  }catch(e){console.error(e)}
})();

function setConnected(on){
  const b=$('connBadge');
  b.className='badge '+(on?'on':'off');
  b.textContent=on?'已连接':'未连接';
  $('main').classList.toggle('hidden',!on);
  $('btnConn').style.display=on?'none':'';
  $('btnDisc').style.display=on?'':'none';
  ['host','user','pwd','sudoPwd'].forEach(id=>$(id).disabled=on);
}
async function doConnect(){
  show('connMsg','正在连接 NAS…','warn');
  $('btnConn').disabled=true;
  try{
    const r=await api('/api/connect',{
      host:$('host').value,user:$('user').value,pwd:$('pwd').value,
      sudo_pwd:$('sudoPwd').value||$('pwd').value,remember:$('remember').checked
    });
    if(!r.ok){show('connMsg',r.error||'连接失败','err');return}
    hide('connMsg');setConnected(true);
    renderScan(r.candidates||[],r.base||'');
    await loadAll();
  }catch(e){show('connMsg','连接出错：'+e.message,'err')}
  finally{$('btnConn').disabled=false}
}
function renderScan(list,cur){
  $('baseNow').textContent=cur||'—';
  $('basePick').innerHTML=(list||[]).map(c=>
    '<option value="'+esc(c.path)+'"'+(c.path===cur?' selected':'')+'>'+
    esc(c.path)+(c.version&&c.version!=='-'?'  ·  v'+esc(c.version):'')+
    (c.valid?'':'  （未检测到配置）')+'</option>'
  ).join('')||'<option value="">未找到候选目录</option>';
}
async function scanBase(manual){
  if(manual)show('baseMsg','正在扫描设备上的 ShellCrash 目录…','warn');
  try{
    const r=await api('/api/scan',{});
    if(!r.ok){if(manual)show('baseMsg',r.error||'扫描失败','err');return}
    renderScan(r.candidates||[],r.current||'');
    if(manual)show('baseMsg','扫描完成：找到 '+r.count+' 个候选，其中 '+r.valid+' 个像有效安装目录。','ok');
  }catch(e){if(manual)show('baseMsg','扫描出错：'+e.message,'err')}
}
async function applyBase(){
  const b=$('basePick').value;
  if(!b)return;
  show('baseMsg','正在切换到 '+b+' …','warn');
  const r=await api('/api/base',{base:b});
  if(!r.ok){show('baseMsg',r.error||'切换失败','err');return}
  $('baseNow').textContent=b;
  show('baseMsg','已切换到 '+b+'，正在重新读取配置…','ok');
  try{await loadAll()}catch(e){}
  show('baseMsg','已切换到 '+b+'。','ok');
}
async function doDisconnect(){
  await api('/api/disconnect',{});setConnected(false);hide('connMsg')
}
async function loadAll(){
  // 各步骤独立容错：某一步失败不再阻断其它数据加载
  try{await loadStatus()}catch(e){console.error('status',e)}
  try{await loadInfo()}catch(e){console.error('info',e)}
  try{await loadGroups()}catch(e){console.error('groups',e)}
  try{await loadRules()}catch(e){console.error('rules',e)}
  try{await loadCgroups()}catch(e){console.error('cgroups',e)}
  try{await loadAllProxies()}catch(e){console.error('proxies',e)}
  // 兜底：若策略组候选仍为空，再单独拉一次，保证"添加规则"可选策略组
  if(!$('groupList').innerHTML.trim()){
    try{await loadGroups()}catch(e){}
  }
}
function fmtBytes(n){
  n=Number(n)||0;
  if(n<1024)return n+' B';
  if(n<1048576)return (n/1024).toFixed(1)+' KB';
  if(n<1073741824)return (n/1048576).toFixed(1)+' MB';
  return (n/1073741824).toFixed(2)+' GB';
}
function statCell(k,v,sub){
  return '<div class="stat"><div class="k">'+k+'</div><div class="v">'+v+
    (sub?' <small>'+sub+'</small>':'')+'</div></div>';
}
async function loadStatus(){
  const s=await api('/api/status',{});
  if(!s.ok){$('statGrid').innerHTML='<div class="muted">状态读取失败：'+esc(s.error||'未知')+'</div>';return}
  const run=s.running;
  const dot='<span class="dot '+(run?'on':'off')+'"></span>';
  const portTxt=[['mixed',s.ports&&s.ports.mixed],['redir',s.ports&&s.ports.redir],
                 ['tproxy',s.ports&&s.ports.tproxy]].filter(x=>x[1])
                 .map(x=>x[0]+':'+x[1]).join(' · ')||'—';
  const modeMap={rule:'规则',direct:'直连',global:'全局'};
  $('statGrid').innerHTML=[
    statCell('内核运行', dot+(run?'运行中':'未运行'), s.pid?('PID '+s.pid):''),
    statCell('内核版本', esc(s.version||'—'), s.meta?'Mihomo Meta':''),
    statCell('运行时长', esc(s.uptime||'—')),
    statCell('内存占用', s.mem_mb?(s.mem_mb+' <small>MB</small>'):'—', s.cpu?('CPU '+esc(s.cpu)):''),
    statCell('代理模式', esc(modeMap[s.mode]||s.mode||'—')),
    statCell('活跃连接', String(s.conns||0)+' <small>条</small>'),
    statCell('累计上传', fmtBytes(s.up_total)),
    statCell('累计下载', fmtBytes(s.down_total)),
    statCell('TUN 模式', esc(s.tun||'—')),
    statCell('转发/端口', esc(s.redir_mod||'—'), portTxt),
    statCell('DNS 模式', esc(s.dns_mod||'—'))
  ].join('');
}
async function loadInfo(){
  const g=await api('/api/groups');
  const ctrl=(g&&g.controller)||'—';
  $('infoLine').innerHTML='外置控制器 <span class="now">'+esc(ctrl)+'</span> &nbsp;·&nbsp; 可切换策略组 <b>'+((g&&g.count)||0)+'</b> 个';
}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}

async function loadGroups(manual){
  // 仅用于填充"添加规则"里的策略组下拉；策略组当前选项界面已移除。
  const r=await api('/api/groups');
  if(!r.ok){if(manual)show('ruleMsg','刷新策略组失败：'+(r.error||'读取失败'),'err');return}
  GROUPS=r.groups||[];
  ALLGROUPS=GROUPS.map(g=>g.name);
  const base=['DIRECT','REJECT'].concat(ALLGROUPS);
  $('groupList').innerHTML=base.map(x=>'<option value="'+esc(x)+'"></option>').join('');
  if(manual)show('ruleMsg','策略组下拉已刷新，共 '+GROUPS.length+' 个。','ok')
}

async function loadRules(){
  const r=await api('/api/rules');
  if(!r.ok){show('ruleMsg',r.error||'读取失败','err');return}
  hide('ruleMsg');$('ruleText').value=r.text||'';renderRuleList()
}
function parseRules(text){
  // 保留分组注释(# ===== xxx =====)作为分组标题，普通规则作为可删除条目
  const out=[];
  (text||'').split('\n').forEach((ln,i)=>{
    const s=ln.trim();
    if(!s)return;
    if(s.startsWith('#')){out.push({line:i+1,raw:ln,group:s.replace(/^#+\s*/,'').replace(/^=+\s*|\s*=+$/g,'').trim()});return}
    out.push({line:i+1,raw:ln});
  });
  return out;
}
function renderRuleList(){
  const list=parseRules($('ruleText').value);
  $('ruleBody').innerHTML=list.map(x=>{
    if(x.group!==undefined){
      return '<tr style="background:#f1f5f9"><td class="muted">'+x.line+'</td>'+
        '<td colspan="2"><b style="color:#334155">▸ '+esc(x.group)+'</b></td></tr>';
    }
    return '<tr><td class="muted">'+x.line+'</td><td><code>'+esc(x.raw.trim())+'</code></td>'+
      '<td><button class="sm danger" onclick="delRule('+x.line+')">删</button></td></tr>';
  }).join('')||'<tr><td colspan="3" class="muted">暂无规则</td></tr>';
}
$('ruleText').addEventListener('input',renderRuleList);

async function addRule(){
  const r=await api('/api/rule/add',{
    type:$('rType').value,value:$('rValue').value.trim(),
    group:$('rGroup').value,note:$('rNote').value.trim()
  });
  if(r.ok){show('ruleMsg','已添加：'+r.rule+'（需重启内核生效，改动前已备份）','ok');
    $('rValue').value='';$('rNote').value='';await loadRules()}
  else show('ruleMsg',r.error||'添加失败','err');
}
function quickAdd(group){$('rGroup').value=group;addRule()}
async function delRule(line){
  const r=await api('/api/rule/delete',{line:line});
  if(r.ok){show('ruleMsg','已删除：'+r.removed+'（需重启内核生效）','ok');await loadRules()}
  else show('ruleMsg',r.error||'删除失败','err');
}
async function saveRules(){
  const r=await api('/api/rule/set',{text:$('ruleText').value});
  if(r.ok){show('ruleMsg','已保存（改动前已备份）'+r.lines+' 行，需重启内核生效','ok');await loadRules()}
  else show('ruleMsg',r.error||'保存失败','err');
}
async function doRestart(){
  $('btnRestart').disabled=true;
  show('ruleMsg','正在重启 ShellCrash 内核…','warn');
  const r=await api('/api/restart',{});
  $('btnRestart').disabled=false;
  if(r.ok){show('ruleMsg','内核已重启，规则已生效。','ok');try{await loadStatus()}catch(e){};await loadInfo()}
  else show('ruleMsg','重启失败：'+(r.error||r.err||'未知'),'err');
}
// ---------- 自定义策略组 ----------
function toggleCgUrl(){
  const t=$('cgType').value;
  $('cgUrlRow').style.display=(t==='select')?'none':'flex';
}
async function loadCgroups(){
  const r=await api('/api/cgroups',{});
  if(!r.ok){show('cgMsg',r.error||'读取失败','err');return}
  $('cgText').value=r.text||'';
  renderCgroups(r.names||[]);
}
function parseCgTypes(text){
  const m={};
  (text||'').split('\n').forEach((ln,i,arr)=>{
    const s=ln.trim();
    if(s.startsWith('- name:')){
      const nm=s.split(':',1)[1].trim().replace(/,+$/,'').replace(/^['"]|['"]$/g,'');
      let type='';
      for(let j=i+1;j<Math.min(i+4,arr.length);j++){
        const t=arr[j].trim();
        if(t.startsWith('type:')){type=t.split(':',1)[1].trim();break}
        if(t.startsWith('- name:'))break;
      }
      m[nm]=type;
    }
  });
  return m;
}
function renderCgroups(names){
  const types=parseCgTypes($('cgText').value);
  $('cgroupBody').innerHTML=(names||[]).map(n=>
    '<tr><td>'+esc(n)+'</td><td><span class="tag">'+esc(types[n]||'—')+'</span></td>'+
    '<td><button class="sm danger" onclick="delCgroup(\''+encodeURIComponent(n)+'\')">删</button></td></tr>'
  ).join('')||'<tr><td colspan="3" class="muted">暂无自定义策略组</td></tr>';
}
async function loadAllProxies(){
  const r=await api('/api/allproxies',{});
  if(!r.ok)return;
  ALLPROXIES=r.proxies||[];
  $('cgMemberPick').innerHTML='<option value="">— 选择节点/策略组 —</option>'+
    ALLPROXIES.map(p=>'<option value="'+esc(p)+'">'+esc(p)+'</option>').join('');
}
function addCgMember(){
  const p=$('cgMemberPick').value;
  if(!p)return;
  const el=$('cgMembers');
  const cur=el.value.trim();
  const arr=cur?cur.split(',').map(x=>x.trim()).filter(Boolean):[];
  if(!arr.includes(p))arr.push(p);
  el.value=arr.join(',');
}
async function addCgroup(){
  const name=$('cgName').value.trim();
  if(!name){show('cgMsg','请填写策略组名称','err');return}
  const members=$('cgMembers').value.split(',').map(x=>x.trim()).filter(Boolean);
  const r=await api('/api/cgroup/add',{
    name:name, type:$('cgType').value,
    proxies:members, url:$('cgUrl').value.trim(),
    interval:parseInt($('cgInterval').value)||300
  });
  if(r.ok){
    show('cgMsg','已新建「'+r.name+'」，'+r.hint+'（改动前已备份）','ok');
    $('cgName').value='';$('cgMembers').value='';
    await loadCgroups();
  }else show('cgMsg',r.error||'新建失败','err');
}
async function delCgroup(encName){
  const name=decodeURIComponent(encName);
  if(!confirm('确定删除自定义策略组「'+name+'」？'))return;
  const r=await api('/api/cgroup/delete',{name:name});
  if(r.ok){show('cgMsg','已删除「'+r.name+'」，'+r.hint,'ok');await loadCgroups()}
  else show('cgMsg',r.error||'删除失败','err');
}
async function saveCgText(){
  const r=await api('/api/cgroup/set',{text:$('cgText').value});
  if(r.ok){show('cgMsg','已保存，'+r.hint+'（改动前已备份）','ok');await loadCgroups()}
  else show('cgMsg',r.error||'保存失败','err');
}
async function restartForGroups(){
  const r=await api('/api/restart',{});
  if(r.ok){show('cgMsg','内核已重启，自定义策略组已生效。','ok');try{await loadStatus()}catch(e){};await loadInfo()}
  else show('cgMsg','重启失败：'+(r.error||r.err||'未知'),'err');
}
async function doExit(){
  try{await api('/api/exit',{})}catch(e){}
  document.body.innerHTML='<div style="padding:40px;text-align:center;color:#6b7280">程序已退出，可以关闭此窗口。</div>';
}
setInterval(()=>{fetch('/api/ping').then(()=>svcLost(false)).catch(()=>svcLost(true))},5000);
// 页面关闭/刷新时通知后台。sendBeacon 能保证在页面卸载时可靠发出。
// 刷新场景：pagehide 发 bye → 新页面加载后 ping 会撤销，不会误关。
function sendBye(){
  try{ if(navigator.sendBeacon){navigator.sendBeacon('/api/bye','')} }catch(e){}
  try{ fetch('/api/bye',{method:'POST',keepalive:true}).catch(()=>{}) }catch(e){}
}
window.addEventListener('pagehide', sendBye);
window.addEventListener('beforeunload', sendBye);
</script>
</body>
</html>
'''


if __name__ == "__main__":
    try:
        main()
    except Exception:
        err = traceback.format_exc()
        try:
            path = os.path.join(os.environ.get("TEMP", "."), "ShellCrashRuleManager-error.log")
            with open(path, "w", encoding="utf-8") as f:
                f.write(err)
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, "启动失败：\n\n" + err[-800:], APP_NAME, 0x10)
        except Exception:
            print(err)
