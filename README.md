# ShellCrash 规则管理器

图形化管理 ShellCrash 的**自定义策略组**和**自定义规则**——Windows 单文件 exe，双击即用，不用敲命令。

![platform](https://img.shields.io/badge/Windows-10%2F11-2563eb) ![remote](https://img.shields.io/badge/远端-免 python3-059669)

> 这是「ShellCrash 部署器」的配套独立项目，部署器见 [spt11cn/fnos-shellcrash](https://github.com/spt11cn/fnos-shellcrash)。
> 两个程序互不冲突，都只监听本机回环地址。

## 它能做什么

- **安装目录扫描**：自动识别 ShellCrash 装在哪里（默认 `/etc/ShellCrash`），支持手动切换
- **内核当前状态**：运行状态、版本、运行时长、内存 / CPU、代理模式、活跃连接、累计流量、TUN、监听端口、转发与 DNS 模式
- **自定义策略组**：新建 / 删除 select / url-test / fallback / load-balance 策略组，成员可从全部节点下拉选择
- **自定义规则**：添加 / 按行号删除 / 直接编辑整个 `yamls/rules.yaml`，按 `# ===== 分组 =====` 分类显示
- **自动备份 + 写入校验**：每次改动前生成带时间戳的 `.bak`，写入后核对字节数
- **一键重启内核**：改完点一下即可生效

## 兼容性

| 设备 | 状态 |
|---|---|
| 飞牛 fnOS（Debian 系，openssh + sudo） | ✅ 支持 |
| iStoreOS / OpenWrt（dropbear，root 免密） | ✅ 已实测（iStoreOS 24.10.2） |

**远端不需要 python3、不需要 base64、不需要 curl。** 程序只通过 SSH 执行 `cat` / `printf` / `sed` / `awk` / `sh start.sh`，
外置控制器（默认 `127.0.0.1:9999`）走 SSH `direct-tcpip` 隧道直连，JSON 解析全在 Windows 本地完成。

## 下载

- 本仓库 [`dist/ShellCrashRuleManager.exe`](dist/ShellCrashRuleManager.exe)
- 或到 [Releases](https://github.com/spt11cn/shellcrash-rule-manager/releases) 取最新版（当前 **v2.1**）

校验（可选）：

```cmd
certutil -hashfile ShellCrashRuleManager.exe SHA256
```

v2.1 的 SHA256：`81417555a3dd9d05d94c46d8d76ce67f36fd9866973c9853ad4ef5e5819ec84d`

## 使用

1. 双击 `ShellCrashRuleManager.exe`，浏览器自动打开 `http://127.0.0.1:8801/`
2. 填设备 IP、用户名、密码 → **连接**（OpenWrt / iStoreOS 免密设备密码留空即可）
3. 自动扫描安装目录 → 核对路径是否识别正确（错了可手动切换）
4. 管理策略组 / 规则，改完点「重启内核使…生效」
5. **关闭网页即自动退出程序**，不用手动结束进程（刷新网页不会误关）

详细说明见 [`使用说明.md`](使用说明.md)。

## 目录结构

```
gui_app.py        本地 HTTP 服务 + 页面 + SSH 执行 + 文件读写 + 控制器隧道
build.py          PyInstaller 打包脚本，产出 dist/ShellCrashRuleManager.exe
使用说明.md        完整使用手册
dist/             打包好的 Windows 单文件 exe
```

## 自己构建

```bash
pip install -r requirements.txt
python build.py
```

## 注意

- 策略组与规则的改动都要**重启内核**才生效；改前会自动备份到同目录 `*.bak.时间戳`。
- 程序只监听 `127.0.0.1`；勾选「记住密码」时用 Windows DPAPI 加密存到 `%APPDATA%\ShellCrashRuleManager\config.json`，换电脑或换 Windows 账号都解不开。

## License

MIT
