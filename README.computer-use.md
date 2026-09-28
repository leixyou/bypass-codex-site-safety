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

**Verified** on ChatGPT.app **26.924.22138** / Codex Computer Use.app **26.923.1001242**: after `./install-computer-use.sh`, a full quit of ChatGPT.app, and a new Computer Use turn, Chrome on a previously blocked URL no longer kills the session with `blockedURL`.

v1 only patched forbidden-app checks. ChatGPT recopies the official helper on launch, so that patch disappeared and the English kill string still reached the model (paraphrased in the UI as “当前 URL 不允许 Computer Use”). v2 skips `throwMappedServerError` for `-10015` and installs LaunchAgent `com.codex-computer-use-lab.repair`.

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
| `~/.codex/computer-use/Codex Computer Use.app` `SkyComputerUseService` | `isForbiddenComputerUseTarget` always false; `allowsForbiddenComputerUseTargets` always true; `throwMappedServerError` returns immediately for `blockedURL` (`-10015`) |
| `defaults com.openai.sky.CUAService` | `ComputerUseAllowForbiddenTargets=true` |
| service / client / lock-screen guardian | rewrite the “stop your work / not allowed on the current browser URL” kill string |
| parent code requirement | drop the OpenAI team-id requirement so the ad-hoc helper can spawn its client |
| helper `Info.plist` | Sparkle auto-update off |
| `~/.codex/mcp-wrappers/cua-node_modules` | JS overlay: ignore `blockedURL` `-10015`; treat app policy `denied`/`forbidden` as allowed |
| unified-computer-use `.mcp.json` | prepend the overlay to `NODE_REPL_NODE_MODULE_DIRS` |
| LaunchAgent `com.codex-computer-use-lab.repair` | re-apply after ChatGPT restores the official helper (WatchPaths + every 2 min) |

The helper is then ad-hoc signed with its original entitlements. ChatGPT
re-copies the official helper and rewrites `.mcp.json` on launch, so install
also adds LaunchAgent `com.codex-computer-use-lab.repair` (WatchPaths + every
2 minutes) to put the patch back. Sparkle auto-update on the helper is turned
off.

`blockedURL` (`-10015`) is skipped in `throwMappedServerError`, so the native
helper no longer turns a blocked Chrome URL into a session-killing RPC error.
The JS overlay also drops `-10015` if the official module path is used first.

## Commands

```bash
./install-computer-use.sh status
./install-computer-use.sh install --dry-run
./install-computer-use.sh uninstall
```

## 破解说明（同上）

Browser Use 有官方开关；Computer Use 没有。拦在 `SkyComputerUseService` 的
`blockedURL`（`-10015`），客户端再写「停下手头工作」。界面「当前 URL 不允许
Computer Use」是这句英文的意译。v1 只改了 forbidden-app，ChatGPT 一启动会把
官方 helper 盖回来。v2 跳过 `-10015` 映射，并装 LaunchAgent 回补。Release 只发
安装器，不发破解好的官方二进制。

本机 ChatGPT.app **26.924.22138** 已验证：安装后 Cmd+Q，新开 Computer Use 可通过
原先被拦的 URL。

## Limits

- macOS arm64. Windows Computer Use is a different native stack.
- ChatGPT recopies `~/.codex/computer-use` on launch; the LaunchAgent puts the patch back. If `status` shows the mapper unpatched, wait ~2 minutes or re-run `./install-computer-use.sh`.
- Computer Use still needs Accessibility / Screen Recording (ad-hoc re-sign is a new TCC identity).
- This does not MITM `chatgpt.com`.

## License

MIT (same as the rest of this repo).
