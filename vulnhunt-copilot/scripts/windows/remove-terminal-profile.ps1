<#
.SYNOPSIS
    Reverts the Copilot agent-terminal setting that configure-terminal-profile.ps1
    wrote during install, if and only if it still looks like our change.

.DESCRIPTION
    install-copilot.cmd's configure-terminal-profile.ps1 points
    chat.tools.terminal.terminalProfile.windows at Git Bash and backs up the
    prior settings.json to settings.json.bak before writing. Uninstalling
    VulnHunter removed the skill files but never touched that setting or the
    backup, leaving Copilot's agent terminal permanently redirected to Git
    Bash with no way to tell it was VulnHunter that did it.

    This script only acts when there's a settings.json.bak next to
    settings.json AND the current value of the setting still points at a
    bash.exe under a Git-for-Windows-shaped path (i.e. it still looks like
    exactly what configure-terminal-profile.ps1 would have written, not
    something the user changed by hand afterward). If either condition
    doesn't hold, it leaves the setting alone and says why -- reverting a
    value the user deliberately changed since install would be worse than
    doing nothing.

    When it does act, it removes only the one property this installer
    added and rewrites the file -- it does NOT restore settings.json from
    the backup wholesale. A user's settings.json accumulates unrelated
    changes (theme, font, extension config) between install and uninstall;
    restoring the whole file from an install-time snapshot would silently
    discard all of that to undo one key. The backup's only job was letting
    configure-terminal-profile.ps1 round-trip the file through
    ConvertFrom-Json/ConvertTo-Json without permanently losing the
    pre-install content if something went wrong during install itself --
    it was never meant to be replayed at uninstall time.

    Called from uninstall-copilot.cmd; safe to run standalone.

.NOTES
    Written and reviewed on macOS -- not run against a real Windows/VS Code
    install. Verify it does what you expect before trusting it in a
    scripted/unattended uninstall.
#>

$ErrorActionPreference = 'Stop'
$SettingKey = 'chat.tools.terminal.terminalProfile.windows'
$SettingsPath = Join-Path $env:APPDATA 'Code\User\settings.json'
$BackupPath = "$SettingsPath.bak"

if (-not (Test-Path -LiteralPath $SettingsPath)) {
    Write-Host "Note: $SettingsPath not found -- nothing to revert."
    exit 0
}

if (-not (Test-Path -LiteralPath $BackupPath)) {
    Write-Host "Note: no $BackupPath found -- either install-copilot.cmd never wrote"
    Write-Host "$SettingKey (it was already set, or VS Code's settings.json wasn't"
    Write-Host "found at install time), so there's nothing for uninstall to revert."
    exit 0
}

try {
    $raw = Get-Content -Raw -LiteralPath $SettingsPath
    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = '{}' }
    $settings = $raw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-Host "Note: could not parse $SettingsPath as JSON -- leaving it and the backup"
    Write-Host "alone rather than risk overwriting something. Restore manually from"
    Write-Host "$BackupPath if you want the pre-install setting back."
    exit 0
}

$existingProp = $settings.PSObject.Properties[$SettingKey]
$currentPath = $null
if ($existingProp -and $existingProp.Value -and $existingProp.Value.path) {
    $currentPath = $existingProp.Value.path
}

# Only revert if the live value still looks like exactly what
# configure-terminal-profile.ps1 writes: a bash.exe path under a
# Git-for-Windows-shaped directory. Anything else -- the key missing, a
# different shape of value, or a path the user pointed somewhere else after
# install -- means don't touch it; the backup's continued presence just
# means uninstall doesn't get to clean it up automatically.
if (-not $currentPath -or $currentPath -notmatch '\\Git\\bin\\bash\.exe$') {
    Write-Host "Note: $SettingKey no longer looks like the Git Bash path this installer"
    Write-Host "set (or the setting was changed since) -- leaving it as-is rather than"
    Write-Host "reverting a change you may have made deliberately."
    Write-Host "The pre-install backup is still at $BackupPath if you want it."
    exit 0
}

# Remove only the one property this installer added -- do not restore the
# whole file from the backup, which would also discard every unrelated
# settings.json change the user made between install and uninstall.
$settings.PSObject.Properties.Remove($SettingKey)
($settings | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $SettingsPath -Encoding UTF8
Remove-Item -LiteralPath $BackupPath -Force
Write-Host "  removed $SettingKey from $SettingsPath"
Write-Host "  (everything else in settings.json was left untouched)"
