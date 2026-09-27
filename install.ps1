<#
.SYNOPSIS
  One-shot Windows installer for bypass-codex-site-safety.

.DESCRIPTION
  Wraps codex_browser_lab.py the same way install.sh does on macOS.
  With no arguments it runs:

      install --preset shopping-cn --persist

  Any arguments you pass are forwarded verbatim, e.g.

      .\install.ps1 status
      .\install.ps1 install --dry-run
      .\install.ps1 install --persist --preset shopping-cn --allow pixiv.net
      .\install.ps1 uninstall

.NOTES
  Needs Windows 10/11, Codex / ChatGPT Desktop installed, Python 3.9+.
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RemainingArgs
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$tool = Join-Path $root 'codex_browser_lab.py'
if (-not (Test-Path -LiteralPath $tool)) {
    throw "codex_browser_lab.py not found next to install.ps1 ($root)"
}

$py = $null
foreach ($cand in @('python', 'python3', 'py')) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) {
    throw 'Python 3.9+ is required but python/python3/py was not found on PATH.'
}

if (-not $RemainingArgs -or $RemainingArgs.Count -eq 0) {
    $RemainingArgs = @('install', '--preset', 'shopping-cn', '--persist')
}

& $py $tool @RemainingArgs
exit $LASTEXITCODE
