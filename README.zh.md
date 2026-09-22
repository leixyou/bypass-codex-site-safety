# bypass-codex-site-safety

[English](README.md) · [中文](README.zh.md) · [Windows 指南](README.windows.md)

在本机绕过 Codex / ChatGPT Desktop 的 **Browser Use site-safety policy**。

Codex 打开淘宝、1688、Pixiv 等站点时，经常直接报：

```text
Browser Use rejected this action due to browser security policy.
Reason: The site-safety policy blocks this action; no user permission prompt or Auto-review was attempted.
Browser use is not permitted on https://www.taobao.com.
```

Settings 里 Allow browsing、`~/.codex/browser/config.toml` 白名单都压不过这层。原因是 **云端** `site_status`，不是 Chrome 扩展权限。

本工具打开客户端里已经存在的 local-testing 开关：

```text
BROWSER_USE_SECURITY_MODE=disabled-for-local-testing
```

从而跳过 `check-url-site-status`。ChatGPT 一更新会把 `~/.codex/config.toml` 里的 `node_repl` 改回去，所以默认安装带 macOS LaunchAgent，更新后再自动补上。

与 OpenAI 无关。不 MITM `chatgpt.com`，也不改 `browser-service.mjs`。

## 实测版本

本机验证过：

| 组件 | 版本 |
|---|---|
| ChatGPT.app | **26.915.31945**（CFBundleVersion 9922） |
| Browser / Chrome 插件（`openai-bundled`） | **26.915.31945** |
| `BROWSER_USE_CODEX_APP_VERSION` | **26.915.31945** |

该版本的 `browser-service.mjs` 仍会把 `BROWSER_USE_SECURITY_MODE=disabled-for-local-testing` 映射为跳过 `check-url-site-status`。ChatGPT 更新常会升这个版本并改写 `node_repl`；再跑 `./install.sh status`，或依赖 `--persist`。

---

## 其他站点要不要手动加？

**不用。** local-testing 模式一旦生效，云端 site-safety 检查对 **所有** `http://` / `https://` 站点都跳过。不是每加一个网站就跑一次 `--allow`。

`--preset` / `--allow` 只写 **本地 origin 白名单**。同一安全模式下 origin-access 也会被跳过，所以白名单是双保险，不是绕过 site-safety 的必要条件。

| 层 | `./install.sh` 之后 |
|---|---|
| 云端 `aura/site_status`（就是 “site-safety policy” 那条报错） | 对所有站点跳过 |
| 本地 origin 白名单 | 可选；默认会写上 `shopping-cn` |
| Computer Use「当前 Chrome URL 不允许」 | **不管** — 另一套杀会话逻辑 |
| 旧会话里模型看到 `site_status` 后拒绕过 | **新开** Codex thread |

`localhost` / `127.0.0.1` 本来就不做 `site_status`。

---

## 一键安装（macOS）

需要：macOS、已安装 ChatGPT.app 或 Codex.app（实测 **26.915.31945**）、Python 3.9+。

```bash
git clone https://github.com/leixyou/bypass-codex-site-safety.git
cd bypass-codex-site-safety
chmod +x install.sh
./install.sh
```

无参数时等于：

```bash
python3 codex_browser_lab.py install --preset shopping-cn --persist
```

然后 **新开一条 Codex thread**（或重启 ChatGPT.app）。已经在跑的 `node_repl` 不会继承新环境变量。

`shopping-cn` 预设会放行：

`taobao.com` · `tmall.com` · `1688.com` · `alicdn.com` · `alipay.com`（主域 + 子域）

这只是方便项。真正全局跳过 site-safety 的是 security mode。

---

## 一键安装（Windows）

需要：Windows 10/11、已安装 Codex / ChatGPT Desktop（先运行一次，让
`%USERPROFILE%\.codex\config.toml` 生成）、Python 3.9+。

```powershell
git clone https://github.com/leixyou/bypass-codex-site-safety.git
cd bypass-codex-site-safety
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

无参数时等于：

```powershell
python codex_browser_lab.py install --preset shopping-cn --persist
```

然后 **重启 Codex / ChatGPT Desktop**（或新开一条 Codex thread）。已经在跑的
`node_repl.exe` 不会继承新环境变量。

Windows 上不需要 wrapper：开关直接写进 Codex 本来就会传给 `node_repl.exe` 的
`[mcp_servers.node_repl.env]` 表，`command` 仍指向官方二进制。`--persist` 装的是
两个计划任务（Scheduled Task），不是 LaunchAgent。详见
[README.windows.md](README.windows.md)。

---

## 这不是浏览器插件

检查发生在 Codex 的 Node 插件 `browser-service.mjs`，每次导航都会请求：

```http
GET https://chatgpt.com/backend-api/aura/site_status
    ?site_url=<目标 URL>
    &url_request_source=codex_browser_use
```

`feature_status.agent === true` 就抛 `site_status_blocked`。官方 Chrome 扩展只是 CDP / native pipe 后端，拦不住这条请求。把官方 Browser Use 再封装成 MCP，只要还走这份 `browser-service.mjs`，淘宝照样挂。

相关 issue：

- [openai/codex#29343](https://github.com/openai/codex/issues/29343) — 1688 / Taobao
- [openai/codex#42932](https://github.com/openai/codex/issues/42932) — Pixiv，用户白名单无效

---

## 命令

```bash
# 是否生效
./install.sh status

# 只跳过 site_status，不动 origin 白名单
python3 codex_browser_lab.py install --persist

# 额外写本地白名单（可选）
python3 codex_browser_lab.py install --persist --preset shopping-cn --allow pixiv.net

# 预览，不写盘
python3 codex_browser_lab.py install --preset shopping-cn --dry-run

# 卸载（保留 origin 白名单）
python3 codex_browser_lab.py uninstall
```

`--persist` 会安装一个自动回补的守护：

| 平台 | 机制 |
|---|---|
| macOS | `~/Library/LaunchAgents/com.codex-browser-lab.repair.plist` |
| Windows | `CodexBrowserLabRepair`（每 5 分钟，可用 `--interval MIN` 调整）加 `CodexBrowserLabRepairLogon`，都执行 `~/.codex/mcp-wrappers/codex-browser-lab-repair.cmd` |

监控 `~/.codex/config.toml` 和插件缓存；ChatGPT 更新改回去之后自动 `repair`。

---

## 改了哪些文件

| 路径 | 作用 |
|---|---|
| `~/.codex/mcp-wrappers/node-repl-security-mode.sh` | wrapper：export 开关，再 `exec` 原版签名过的 `node_repl` |
| `~/.codex/config.toml` `[mcp_servers.node_repl]` | `command` 指向 wrapper；写入 `BROWSER_USE_SECURITY_MODE` |
| `~/.codex/config.toml` `[browser_use.origins.*]` | 可选 origin 放行表 |
| `~/.codex/browser/config.toml` | 可选 `allowed` 数组 |
| `~/.codex/plugins/cache/openai-bundled/unified-computer-use/*/.mcp.json` | CUA 环境变量 + `CUA_REPL_NODE_REPL_PATH` |

wrapper 用 `exec`，运行中的进程镜像仍是官方 `node_repl`，native pipe 的代码签名身份不变。

**Windows** 上不生成 wrapper：上表只有第 2–5 行适用，`command` 保持指向官方
`node_repl.exe`。见 [README.windows.md](README.windows.md)。

**不会做的事：**

- 不劫持 `chatgpt.com/backend-api/aura/site_status`
- 不改 `browser-service.mjs`（升级即失效）
- 不动 Computer Use 那套「当前 Chrome URL 不允许」的独立杀会话逻辑

---

## 怎么确认生效

```bash
python3 codex_browser_lab.py status
```

期望：

```text
config command      .../mcp-wrappers/node-repl-security-mode.sh
config security     disabled-for-local-testing
config ok           True
live pid=...        mode=disabled-for-local-testing
```

`config ok true` 但 live process 仍是 `<unset>`：配置已写上，当前会话还是旧进程。新开 thread。

更新 ChatGPT 后再跑一次 `status`。若 `config ok false` 且装了 `--persist`，等几秒让 LaunchAgent 回补；没有 persist 就再执行 `./install.sh`。

---

## 限制

- **模型拒绕过**：旧会话里已经吃过 `site_status` 错误时，模型可能按「禁止 workaround」拒绝继续。换新 thread。
- **Computer Use**：Chrome 停在被拦 URL 上时，Computer Use 仍可能整段停掉。本工具只管 Browser Use / Chrome plugin。
- **更新覆盖**：插件缓存目录名随版本变。`--persist` 就是为这个准备的。
- 已支持 macOS（LaunchAgent）与 Windows（计划任务 Scheduled Task）。

---

## 卸载

```bash
python3 codex_browser_lab.py uninstall
```

恢复官方 `node_repl` 路径、删掉 env 开关和 LaunchAgent。origin 白名单默认保留，要删自己改 `config.toml`。

## License

MIT
