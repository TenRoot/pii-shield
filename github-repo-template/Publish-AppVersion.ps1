<#
.SYNOPSIS
  Stamp app/version.json with the version and SHA-256 of app/pii_sanitizer.py.
.EXAMPLE
  ./Publish-AppVersion.ps1 -Notes "Adds CS_CID recognizer support"
#>
[CmdletBinding()]
param(
    [string]$ScriptPath = "app/pii_sanitizer.py",
    [string]$Notes = ""
)
$ErrorActionPreference = 'Stop'
$content = Get-Content $ScriptPath -Raw
if ($content -notmatch '__version__\s*=\s*"([^"]+)"') { throw "__version__ not found in $ScriptPath" }
$version = $Matches[1]
$hash = (Get-FileHash $ScriptPath -Algorithm SHA256).Hash.ToLower()
[ordered]@{
    version     = $version
    script_path = $ScriptPath -replace '\\', '/'
    sha256      = $hash
    notes       = $Notes
    published   = (Get-Date).ToString('yyyy-MM-dd')
} | ConvertTo-Json | Set-Content app/version.json -Encoding utf8
Write-Host "app/version.json -> v$version ($hash)"
