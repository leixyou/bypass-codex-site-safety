# bypass-codex-site-safety

[English](README.md) · [中文](README.zh.md) · [Windows 指南](README.windows.md) · [Computer Use](README.computer-use.md)

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

从而跳过 `check-url-site-status`。ChatGPT 一更新会把 `~/.codex/config.toml` 改回去，所以默认安装带自动回补（macOS LaunchAgent；Windows 上是 HKCU Run 守护进程 + 计划任务）。

与 OpenAI 无关。不 MITM `chatgpt.com`。会改本地插件缓存，让 local-testing 开启时忽略 `Page.navigationBlocked`；应用更新会覆盖该文件，`--persist` 会再打回去。

## 实测版本

本机验证过：

| 组件 | 版本 |
|---|---|
| ChatGPT.app | **26.924.22138** |
| Browser / Chrome 插件（`openai-bundled`） | **26.924.22138** |
| `BROWSER_USE_CODEX_APP_VERSION` | **26.924.22138** |
| Codex Computer Use.app | **26.923.1001242** |

该版本的 `browser-service.mjs` 仍会把 `BROWSER_USE_SECURITY_MODE=disabled-for-local-testing` 映射为跳过 `check-url-site-status`。ChatGPT 更新常会升这个版本并改写 `node_repl`；再跑 `./install.sh status`，或依赖 `--persist`。

Windows（Codex Desktop **26.915.4065.0** / 插件 **26.915.31945**）见 [README.windows.md](README.windows.md)。

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

### 微信小程序后台点某个功能仍被拦

能打开后台，但一点具体功能就报「浏览器安全策略禁止操作当前网址」——这经常 **不是** `site_status`。点击后 Chrome CDP 会发 `Page.navigationBlocked`，插件再抛 `browser_navigation_blocked`，文案同样是 “not permitted”。local-testing 原先不跳过这条。

`./install.sh` 现在会顺手改缓存里的 `browser-service.mjs`，在开关打开时忽略该事件。然后 **新开 thread**。

仍然不管：

- **Computer Use 操作 Chrome**，且前台是 `mp.weixin.qq.com` 等被拦域名——另一套杀会话，不是 Browser Use。
- 微信后台检测到 Chrome debugger，自己弹出安全验证页。
- 模型确认策略（发布 / 支付 / 改权限）。需要你在对话里明确授权该操作。

用 `@Chrome` / Browser Use 认领你已经登录的标签，不要用 Computer Use 去点那个标签。

---

## 一键安装（macOS Computer Use）

Computer Use 在 Chrome 停在被拦 URL 上时会用原生 `blockedURL`（`-10015`）杀掉会话。这层**不受** `BROWSER_USE_SECURITY_MODE` 控制。

```bash
chmod +x install-computer-use.sh
./install-computer-use.sh
```

改的是 `~/.codex/computer-use/Codex Computer Use.app` 和一份 JS overlay。然后重启 ChatGPT.app，**新开** Computer Use。详见 [README.computer-use.md](README.computer-use.md)。

---

## 一键安装（macOS）

需要：macOS、已安装 ChatGPT.app 或 Codex.app（实测 **26.917.62051**）、Python 3.9+。

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

Windows 上不需要 wrapper：开关直接写进 `[mcp_servers.node_repl.env]` 表，`command` 仍指向
官方二进制。注意 Codex **每次启动都会重写整个 `node_repl` 块**，而且 `node_repl` 的环境由
Codex 自己拼装（所以 `setx` 的系统变量传不进去）——`--persist` 因此装了一个小守护进程，
在约两秒内把补丁补回去，之后 **新开一条 Codex thread** 即可生效。详见
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
| Windows | HKCU `Run` 守护进程，约 2 秒内自动补回补丁；另加 `CodexBrowserLabRepair` 计划任务（每 5 分钟，`--interval MIN` 可调）兜底 |

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
| `~/.codex/plugins/cache/.../{chrome,browser}/*/scripts/browser-service.mjs` | local-testing 开启时忽略 CDP `Page.navigationBlocked` |

wrapper 用 `exec`，运行中的进程镜像仍是官方 `node_repl`，native pipe 的代码签名身份不变。

**Windows** 上不生成 wrapper：`command` 保持指向官方 `node_repl.exe`，开关写进
`[mcp_servers.node_repl.env]`，`Page.navigationBlocked` 的缓存补丁仍然会打。Codex
每次启动都会重写 `node_repl` 块，所以靠守护进程回补。见 [README.windows.md](README.windows.md)。

**不会做的事：**

- 不劫持 `chatgpt.com/backend-api/aura/site_status`
- 不改应用包本身（只动本地插件缓存，更新后由 `--persist` 再打）
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

更新 ChatGPT 后再跑一次 `status`。若 `config ok false` 且装了 `--persist`，等几秒让守护回补；没有 persist 就再执行 `./install.sh` 或 `.\install.ps1`。

---

## 限制

- **模型拒绕过**：旧会话里已经吃过 `site_status` 错误时，模型可能按「禁止 workaround」拒绝继续。换新 thread。
- **Computer Use**：Chrome 停在被拦 URL 上时，Computer Use 仍可能整段停掉。本工具只管 Browser Use / Chrome plugin。
- **更新覆盖**：插件缓存目录名随版本变。`--persist` 就是为这个准备的。
- 已支持 macOS（LaunchAgent）与 Windows（HKCU Run 守护进程 + 计划任务）。

---

## 卸载

```bash
python3 codex_browser_lab.py uninstall
```

恢复官方 `node_repl` 路径、删掉 env 开关，以及 LaunchAgent / Windows 守护。origin 白名单默认保留，要删自己改 `config.toml`。

## License

MIT
