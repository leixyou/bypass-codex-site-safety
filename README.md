# bypass-codex-site-safety

Bypass Codex / ChatGPT Desktop **Browser Use site-safety policy** on your own machine.

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

Not affiliated with OpenAI. Uses a flag the official plugin already implements. Does not MITM `chatgpt.com` and does not patch `browser-service.mjs`.

---

## 一键安装（macOS）

需要：macOS、已安装 ChatGPT.app 或 Codex.app、Python 3.9+。

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

`localhost` / `127.0.0.1` 本身不做 `site_status`。本工具不走反代，只开插件自带的 testing mode。

---

## 命令

```bash
# 是否生效
./install.sh status

# 只跳过 site_status，不动 origin 白名单
python3 codex_browser_lab.py install --persist

# 额外站点
python3 codex_browser_lab.py install --persist --preset shopping-cn --allow pixiv.net

# 预览，不写盘
python3 codex_browser_lab.py install --preset shopping-cn --dry-run

# 卸载（保留 origin 白名单）
python3 codex_browser_lab.py uninstall
```

`--persist` 会安装：

`~/Library/LaunchAgents/com.codex-browser-lab.repair.plist`

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
- macOS only（LaunchAgent）。Windows 需要的话请开 issue。

---

## 卸载

```bash
python3 codex_browser_lab.py uninstall
```

恢复官方 `node_repl` 路径、删掉 env 开关和 LaunchAgent。origin 白名单默认保留，要删自己改 `config.toml`。

---

## English

Codex Browser Use asks `https://chatgpt.com/backend-api/aura/site_status` before every navigation. A positive `feature_status.agent` fails closed with *site-safety policy*, even when the user allowlisted the origin. This repo enables the plugin’s own `BROWSER_USE_SECURITY_MODE=disabled-for-local-testing`, which skips that check, and optionally expands origin allowlists.

```bash
git clone https://github.com/leixyou/bypass-codex-site-safety.git
cd bypass-codex-site-safety
./install.sh          # macOS: shopping-cn preset + LaunchAgent
./install.sh status
```

Start a **new** Codex thread afterwards. MIT licensed. Not affiliated with OpenAI.
