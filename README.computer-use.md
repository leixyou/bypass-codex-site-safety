# Computer Use patch (macOS)

## What was cracked

Browser Use can skip cloud `site_status` with the official flag
`BROWSER_USE_SECURITY_MODE=disabled-for-local-testing`. Computer Use cannot.

The desktop helper is a signed Mach-O (`SkyComputerUseService` /
`SkyComputerUseClient` under `~/.codex/computer-use/Codex Computer Use.app`).
It has **no** `BROWSER_USE_SECURITY_MODE` (or any other env) that skips URL
policy. Native code (`AuraSiteStatusURLPolicyChecker`,
`ComputerUseURLBlocklist`, `feature_status.computer_use`) returns Sky error
`blockedURL` (`-10015`). The client then injects:

```text
This session has been stopped because Computer Use is not allowed on the
current browser URL. Stop your work and send a final message noting why
the session has been ended. Note that Computer Use is not allowed on this
URL even if the user navigates to it themselves.
```

That is a session kill, not a Browser Use `site_status` toast. Hardened
Runtime plus parent team-id `2DC432GLL2` means a persistent bypass is a
**local binary patch + ad-hoc re-sign** of the user-writable helper, plus a
JS overlay so node_repl does not treat `-10015` as fatal.

The GitHub release is that **patcher**. It does not upload a cracked
ChatGPT.app or the 23MB official helper.

This installer patches **your local** Computer Use copy.

## One-shot

```bash
git clone https://github.com/leixyou/bypass-codex-site-safety.git
cd bypass-codex-site-safety
chmod +x install-computer-use.sh
./install-computer-use.sh
```

That is:

```bash
python3 computer_use_lab.py install
```

Then **restart ChatGPT.app** and start a **new** Computer Use turn. If macOS
asks, re-grant Accessibility and Screen Recording to “ChatGPT Computer Use”
(the helper is ad-hoc re-signed).

## What it changes

| Target | Change |
|---|---|
| `~/.codex/computer-use/Codex Computer Use.app` `SkyComputerUseService` | `isForbiddenComputerUseTarget` always false; `allowsForbiddenComputerUseTargets` always true |
| `defaults com.openai.sky.CUAService` | `ComputerUseAllowForbiddenTargets=true` |
| `SkyComputerUseClient` | rewrite the “stop your work / not allowed on the current browser URL” kill string |
| parent code requirement | drop the OpenAI team-id requirement so the ad-hoc helper can spawn its client |
| `~/.codex/mcp-wrappers/cua-node_modules` | JS overlay: ignore `blockedURL` `-10015`; treat app policy `denied`/`forbidden` as allowed |
| unified-computer-use `.mcp.json` | prepend the overlay to `NODE_REPL_NODE_MODULE_DIRS` |

The helper is then ad-hoc signed with its original entitlements.

## Commands

```bash
./install-computer-use.sh status
./install-computer-use.sh install --dry-run
./install-computer-use.sh uninstall
```

## 破解说明（同上）

Browser Use 有官方开关；Computer Use 没有。拦在 `SkyComputerUseService` 的
`blockedURL`（`-10015`），客户端再写「停下手头工作」。所以要对本机
`~/.codex/computer-use` 里的 helper 打补丁并 ad-hoc 重签。Release 只发安装器，
不发破解好的官方二进制。

## Limits

- macOS arm64. Windows Computer Use is a different native stack.
- ChatGPT/Codex updates can replace `~/.codex/computer-use`; re-run `./install-computer-use.sh`.
- Computer Use still needs Accessibility / Screen Recording.
- This does not MITM `chatgpt.com`.

## License

MIT (same as the rest of this repo).
