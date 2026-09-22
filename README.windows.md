# Windows guide — bypass-codex-site-safety

This is the Windows port of [bypass-codex-site-safety](README.md). It turns on
Codex / ChatGPT Desktop **Browser Use local-testing mode** on a Windows machine,
so the cloud `aura/site_status` ("site-safety policy") check is skipped for every
`http://` / `https://` site.

## Requirements

| Component | Needed |
|---|---|
| Windows | 10 or 11 (x64) |
| Codex / ChatGPT Desktop | installed and run at least once (so `%USERPROFILE%\.codex\config.toml` exists) |
| Python | 3.9+ (`python`, `python3` or the `py` launcher on PATH) |

Check the prerequisites:

```powershell
node_repl_path = "$env:LOCALAPPDATA\OpenAI\Codex\runtimes\cua_node"
Get-ChildItem $node_repl_path -Recurse -Filter node_repl.exe | Select-Object FullName
Test-Path "$env:USERPROFILE\.codex\config.toml"
```

## Install

```powershell
git clone https://github.com/leixyou/bypass-codex-site-safety.git
cd bypass-codex-site-safety
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

With no arguments that is exactly:

```powershell
python codex_browser_lab.py install --preset shopping-cn --persist
```

Then **restart Codex / ChatGPT Desktop** (or at least start a new Codex thread).
Already-running `node_repl.exe` processes keep the old environment.

## How the Windows port differs from macOS

| | macOS | Windows |
|---|---|---|
| Injection point | bash wrapper that `export`s the flag, then `exec`s the signed `node_repl` — `command` in `config.toml` is repointed at it | the existing `[mcp_servers.node_repl.env]` table — **`command` is left untouched** |
| Wrapper file | `~/.codex/mcp-wrappers/node-repl-security-mode.sh` | none (nothing to wrap) |
| Persistence | LaunchAgent with `WatchPaths` | two Scheduled Tasks + a tiny `.cmd` shim |
| `node_repl` discovery | `/Applications/{ChatGPT,Codex}.app/...` | `%LOCALAPPDATA%\OpenAI\Codex\runtimes\cua_node\*\bin\node_repl.exe` (newest), or the `command` already in `config.toml` |
| Live check | `pgrep` + `ps eww` | `tasklist` + reading each process's PEB environment block via `ReadProcessMemory` |

The Windows path needs no wrapper at all: Codex already ships a
`[mcp_servers.node_repl.env]` table that it passes straight to `node_repl.exe`,
so the variable is set there and the official signed binary stays in place.

## Commands

```powershell
# is it active?
.\install.ps1 status

# skip site_status only; do not touch origin allowlists
.\install.ps1 install --persist

# extra local allowlist entries (optional)
.\install.ps1 install --persist --preset shopping-cn --allow pixiv.net

# preview, no writes
.\install.ps1 install --preset shopping-cn --dry-run

# uninstall (keeps origin allowlists)
.\install.ps1 uninstall
```

`--persist` registers two per-user Scheduled Tasks:

| Task | Trigger | Purpose |
|---|---|---|
| `CodexBrowserLabRepair` | every 5 minutes (`--interval MIN` to change) | re-applies the patch after a Codex/ChatGPT update rewrites `config.toml` |
| `CodexBrowserLabRepairLogon` | at logon | immediate re-apply after a reboot |

Both run `~/.codex/mcp-wrappers/codex-browser-lab-repair.cmd`, which calls the
installed copy of the tool with `repair` and appends output to
`~/.codex/mcp-wrappers/codex-browser-lab.log`.

Inspect or remove them by hand if you prefer:

```powershell
schtasks /Query /TN CodexBrowserLabRepair /V /FO LIST
schtasks /Delete /TN CodexBrowserLabRepair /F
schtasks /Delete /TN CodexBrowserLabRepairLogon /F
```

## Files it changes on Windows

| Path | Role |
|---|---|
| `~/.codex/config.toml` `[mcp_servers.node_repl.env]` | adds `BROWSER_USE_SECURITY_MODE` (the actual bypass) |
| `~/.codex/config.toml` `[browser_use.origins.*]` | optional origin allow tables (`--preset` / `--allow`) |
| `~/.codex/browser/config.toml` | optional `allowed` arrays |
| `~/.codex/plugins/cache/openai-bundled/unified-computer-use/*/.mcp.json` | CUA env flag |
| `~/.codex/mcp-wrappers/` | installed tool copy, `repair` shim, log, `backups/` of every file touched |

`~/.codex/mcp-wrappers/backups/` keeps a timestamped copy of each file before it
is written, and uninstall restores the official values.

## Verify

```powershell
.\install.ps1 status
```

You want:

```text
platform            win32
CODEX_HOME          C:\Users\<you>\.codex
official node_repl  ...\runtimes\cua_node\<hash>\bin\node_repl.exe
persist             CodexBrowserLabRepair=installed CodexBrowserLabRepairLogon=installed
repair shim         ...\mcp-wrappers\codex-browser-lab-repair.cmd exists=True
config command      ...\runtimes\cua_node\<hash>\bin\node_repl.exe
config security     disabled-for-local-testing
config ok           True
live pid=1234       mode=disabled-for-local-testing
```

Exit codes: `0` active, `2` config not patched, `3` config patched but the running
processes still carry the old environment (restart the app).

`mode=<unreadable>` for a live PID means Windows refused the `ReadProcessMemory`
call for that process — on a normal same-user install this does not happen; it
just means the live check could not confirm that PID. The config check is
authoritative either way.

## Uninstall

```powershell
.\install.ps1 uninstall
```

Removes both Scheduled Tasks, the `.cmd` shim, the `BROWSER_USE_SECURITY_MODE`
key from `config.toml` and the CUA `.mcp.json`. Origin allowlists are left in
place unless you delete them from `config.toml` yourself.

## Limits

- **Model refusal:** if an old thread already saw a `site_status` error, the model
  may refuse to continue. Use a new thread.
- **Computer Use:** Chrome sitting on a blocked URL can still abort a Computer Use
  session. This tool only covers Browser Use / the Chrome plugin.
- **Updates:** a Codex/ChatGPT update rewrites `config.toml`. That is what
  `--persist` is for; without it, re-run `.\install.ps1`.
- **Side effects:** `disabled-for-local-testing` bypasses more than
  `check-url-site-status` — it also removes user-consent prompts for
  `browser-history-read`, `browser-origin-access`, `check-navigation-url-policy`,
  `file-download`, `file-upload`, `full-cdp`, `page-asset-*` and
  `raw-cdp-destination-url`. The browser agent becomes more autonomous inside your
  own browser profile. Uninstall to restore the prompts.

## License

MIT (same as upstream).
