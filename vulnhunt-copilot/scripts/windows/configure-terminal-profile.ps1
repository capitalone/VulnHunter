<#
.SYNOPSIS
    Points Copilot Chat's agent terminal tool at Git Bash on Windows.

.DESCRIPTION
    The VulnHunter skills (SKILL.md, prompts/*.md, phases/*.md) embed bash
    syntax in their code blocks (${VAR} expansion, [ ] tests, heredocs).
    VS Code Copilot's "run in terminal" tool defaults to whatever the
    workspace's default terminal profile is, which on Windows is normally
    PowerShell or cmd.exe -- neither understands that syntax.

    VS Code has a setting specifically for this, separate from the general
    default terminal profile, confirmed against VS Code's own source
    (terminalChatAgentToolsConfiguration.ts):

        chat.tools.terminal.terminalProfile.windows

    This script sets it to the Git Bash executable, without touching any
    other setting or your regular integrated terminal's default profile.

    Called from install-copilot.cmd; not meant to be run standalone, though
    it's safe to (it no-ops cleanly if anything looks off).

.PARAMETER GitBashPath
    Absolute path to bash.exe (Git for Windows). Required.

.NOTES
    Written and reviewed on macOS -- not run against a real Windows/VS Code
    install. Verify it does what you expect before trusting it in a
    scripted/unattended install.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$GitBashPath
)

$ErrorActionPreference = 'Stop'
$SettingKey = 'chat.tools.terminal.terminalProfile.windows'
$SettingsPath = Join-Path $env:APPDATA 'Code\User\settings.json'

function Show-ManualInstructions {
    Write-Host "Add this to your VS Code settings.json yourself if you want it:"
    Write-Host "  `"$SettingKey`": { `"path`": `"$($GitBashPath -replace '\\','\\')`" }"
}

if (-not (Test-Path -LiteralPath $SettingsPath)) {
    Write-Host "Note: $SettingsPath not found -- skipping automatic Copilot terminal profile setup."
    Write-Host "(VS Code Stable may not be installed under this user profile, or you're on Insiders"
    Write-Host " -- check %APPDATA%\Code - Insiders\User\settings.json instead.)"
    Show-ManualInstructions
    exit 0
}

try {
    $raw = Get-Content -Raw -LiteralPath $SettingsPath
    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = '{}' }
    $settings = $raw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-Host "Note: could not parse $SettingsPath as JSON (it may contain comments or trailing"
    Write-Host "commas, which plain JSON parsers reject even though VS Code allows them)."
    Write-Host "Skipping automatic setup to avoid corrupting it."
    Show-ManualInstructions
    exit 0
}

$existingProp = $settings.PSObject.Properties[$SettingKey]
if ($existingProp -and $existingProp.Value -and $existingProp.Value.path) {
    if ($existingProp.Value.path -eq $GitBashPath) {
        Write-Host "  $SettingKey already points at Git Bash -- nothing to do."
        exit 0
    }
    Write-Host "Note: $SettingKey is already set to a different path:"
    Write-Host "  $($existingProp.Value.path)"
    Write-Host "Leaving your existing setting alone. If VulnHunter skills fail with shell syntax"
    Write-Host "errors on Windows, consider pointing it at Git Bash instead:"
    Write-Host "  $GitBashPath"
    exit 0
}

# Back up before writing -- ConvertTo-Json round-trips the whole file and
# will drop any comments (VS Code's settings.json is JSONC, plain JSON
# parsers aren't) or reformat things you had arranged a particular way.
$backupPath = "$SettingsPath.bak"
Copy-Item -LiteralPath $SettingsPath -Destination $backupPath -Force
Write-Host "  backed up settings.json to $backupPath"

$profileValue = [PSCustomObject]@{ path = $GitBashPath }
if ($existingProp) {
    $settings.$SettingKey = $profileValue
}
else {
    $settings | Add-Member -NotePropertyName $SettingKey -NotePropertyValue $profileValue
}

($settings | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $SettingsPath -Encoding UTF8
Write-Host "  set $SettingKey -> $GitBashPath"
Write-Host "  (original backed up to $backupPath -- restore it if this settings.json now looks wrong)"
