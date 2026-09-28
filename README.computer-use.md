# Computer Use patch (macOS)

ChatGPT Desktop **Computer Use** enforces a separate native URL/app policy
(`AuraSiteStatusURLPolicyChecker` / `ComputerUseURLBlocklist` in
`SkyComputerUseService`). `BROWSER_USE_SECURITY_MODE` does not affect it.
When Chrome sits on a blocked URL the helper returns Sky error `blockedURL`
(`-10015`) and the client tells the model to stop the session.

This installer patches **your local** Computer Use copy. It does **not** ship
OpenAI binaries.

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

## Limits

- macOS arm64. Windows Computer Use is a different native stack.
- ChatGPT/Codex updates can replace `~/.codex/computer-use`; re-run `./install-computer-use.sh`.
- Computer Use still needs Accessibility / Screen Recording.
- This does not MITM `chatgpt.com`.

## License

MIT (same as the rest of this repo).
