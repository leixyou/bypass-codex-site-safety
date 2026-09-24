# bypass-codex-site-safety

[English](README.md) · [中文](README.zh.md)

Bypass Codex / ChatGPT Desktop **Browser Use site-safety policy** on your own machine.

When Codex opens Taobao, 1688, Pixiv, and similar sites it often fails immediately with:

```text
Browser Use rejected this action due to browser security policy.
Reason: The site-safety policy blocks this action; no user permission prompt or Auto-review was attempted.
Browser use is not permitted on https://www.taobao.com.
```

Allowing the site in Settings or in `~/.codex/browser/config.toml` does not override this. The decision is a **cloud** `site_status` check, not a Chrome-extension permission.

This tool turns on a flag the official plugin already implements:

```text
BROWSER_USE_SECURITY_MODE=disabled-for-local-testing
```

That skips `check-url-site-status`. ChatGPT updates rewrite `~/.codex/config.toml` and drop the `node_repl` wrap, so the default install also adds a macOS LaunchAgent that re-applies the patch.

Not affiliated with OpenAI. Does not MITM `chatgpt.com` and does not patch `browser-service.mjs`.

## Tested on

Verified locally against:

| Component | Version |
|---|---|
| ChatGPT.app | **26.917.62051** |
| Browser / Chrome plugin (`openai-bundled`) | **26.917.62051** |
| `BROWSER_USE_CODEX_APP_VERSION` | **26.917.62051** |

On this build, `browser-service.mjs` still maps `BROWSER_USE_SECURITY_MODE=disabled-for-local-testing` to skipping `check-url-site-status`. ChatGPT updates often bump this version and rewrite `node_repl`; re-run `./install.sh status` or rely on `--persist`.

---

## Do I have to add every site?

**No.** Once local-testing mode is on, the cloud site-safety check is skipped for **all** `http://` and `https://` hosts. You do not run `--allow` per site to bypass *site-safety policy*.

`--preset` / `--allow` only write **local origin allowlists**. In this same security mode, origin-access is also skipped, so those lists are belt-and-suspenders, not required for the bypass.

| Layer | After `./install.sh` |
|---|---|
| Cloud `aura/site_status` (the “site-safety policy” error) | Skipped for every site |
| Local origin allowlist | Optional; `shopping-cn` is applied by default |
| Computer Use “this Chrome URL is not allowed” | **Not** covered — separate kill switch |
| Model refusing after an old `site_status` error | Use a **new** Codex thread |

`localhost` / `127.0.0.1` were already exempt from `site_status`.

### Still blocked on WeChat mini-program admin (or similar)

If **open** works but **clicking a feature** fails with “browser security policy / not permitted on the current URL”, that is often **not** `site_status`. After a click, Chrome CDP can emit `Page.navigationBlocked`; the plugin then throws `browser_navigation_blocked` with the same “not permitted” wording. Local-testing mode did not skip that path.

`./install.sh` now also patches cached `browser-service.mjs` so that event is ignored while the flag is on. Then start a **new** thread.

Still not covered:

- **Computer Use on Chrome** while `mp.weixin.qq.com` (or another blocked host) is the front tab — a separate session killer, not Browser Use.
- WeChat admin detecting Chrome’s debugger and showing its own security page.
- Model confirmation policy (publish / pay / change permissions). Say explicitly that you authorize that action.

Prefer `@Chrome` / Browser Use on a tab you already logged in. Do not drive that tab with Computer Use.

---

## One-shot install (macOS)

Needs: macOS, ChatGPT.app or Codex.app **26.915.31945** (tested), Python 3.9+.

```bash
git clone https://github.com/leixyou/bypass-codex-site-safety.git
cd bypass-codex-site-safety
chmod +x install.sh
./install.sh
```

With no arguments that is:

```bash
python3 codex_browser_lab.py install --preset shopping-cn --persist
```

Then start a **new Codex thread** (or restart ChatGPT.app). Already-running `node_repl` processes keep the old environment.

The `shopping-cn` preset allowlists:

`taobao.com` · `tmall.com` · `1688.com` · `alicdn.com` · `alipay.com` (apex + subdomains)

That preset is convenience only. Security mode is what bypasses site-safety globally.

---

## This is not a Chrome extension

The check runs in Codex’s Node plugin `browser-service.mjs`. Every navigation hits:

```http
GET https://chatgpt.com/backend-api/aura/site_status
    ?site_url=<target URL>
    &url_request_source=codex_browser_use
```

If `feature_status.agent === true`, the plugin throws `site_status_blocked`. The official Chrome extension is only the CDP / native-pipe backend; it never sees this request. Wrapping official Browser Use as MCP still fails on Taobao if it still loads that `browser-service.mjs`.

Related issues:

- [openai/codex#29343](https://github.com/openai/codex/issues/29343) — 1688 / Taobao
- [openai/codex#42932](https://github.com/openai/codex/issues/42932) — Pixiv; user allowlist ignored

---

## Commands

```bash
# is it active?
./install.sh status

# skip site_status only; do not touch origin allowlists
python3 codex_browser_lab.py install --persist

# extra local allowlist entries (optional)
python3 codex_browser_lab.py install --persist --preset shopping-cn --allow pixiv.net

# preview, no writes
python3 codex_browser_lab.py install --preset shopping-cn --dry-run

# uninstall (keeps origin allowlists)
python3 codex_browser_lab.py uninstall
```

`--persist` installs:

`~/Library/LaunchAgents/com.codex-browser-lab.repair.plist`

It watches `~/.codex/config.toml` and the plugin cache. After a ChatGPT update reverts the wrap, `repair` runs again.

---

## Files it changes

| Path | Role |
|---|---|
| `~/.codex/mcp-wrappers/node-repl-security-mode.sh` | Wrapper: export the flag, then `exec` the signed `node_repl` |
| `~/.codex/config.toml` `[mcp_servers.node_repl]` | Point `command` at the wrapper; set `BROWSER_USE_SECURITY_MODE` |
| `~/.codex/config.toml` `[browser_use.origins.*]` | Optional origin allow tables |
| `~/.codex/browser/config.toml` | Optional `allowed` arrays |
| `~/.codex/plugins/cache/openai-bundled/unified-computer-use/*/.mcp.json` | CUA env + `CUA_REPL_NODE_REPL_PATH` |
| `~/.codex/plugins/cache/.../{chrome,browser}/*/scripts/browser-service.mjs` | Ignore CDP `Page.navigationBlocked` while local-testing mode is on |

The wrapper uses `exec`, so the running image is still official `node_repl` and the native-pipe code-signing identity does not change.

It does **not**:

- Intercept `chatgpt.com/backend-api/aura/site_status`
- Patch `browser-service.mjs` (that dies on the next upgrade)
- Touch Computer Use’s separate “current Chrome URL is not allowed” session killer

---

## Verify

```bash
python3 codex_browser_lab.py status
```

You want:

```text
config command      .../mcp-wrappers/node-repl-security-mode.sh
config security     disabled-for-local-testing
config ok           True
live pid=...        mode=disabled-for-local-testing
```

`config ok true` but live processes still `<unset>`: the file is patched, the current session is an old process. Open a new thread.

After a ChatGPT update, run `status` again. If `config ok false` and you installed `--persist`, wait a few seconds for the LaunchAgent. Without persist, re-run `./install.sh`.

---

## Limits

- **Model refusal:** if an old thread already saw a `site_status` error, the model may refuse to continue (“no workarounds”). Use a new thread.
- **Computer Use:** if Chrome is sitting on a blocked URL, Computer Use can still abort the session. This tool only covers Browser Use / the Chrome plugin.
- **Updates:** plugin cache directory names change with the app version. That is why `--persist` exists.
- macOS only (LaunchAgent). Open an issue if you need Windows.

---

## Uninstall

```bash
python3 codex_browser_lab.py uninstall
```

Restores the official `node_repl` path, removes the env flag and LaunchAgent. Origin allowlists are left in place unless you delete them from `config.toml` yourself.

## License

MIT
