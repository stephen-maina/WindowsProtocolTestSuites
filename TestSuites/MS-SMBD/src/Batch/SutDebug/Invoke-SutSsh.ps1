# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.
<#
.SYNOPSIS
    Runs one command on the Linux SUT (ksmbd) over SSH, using the credentials in the suite's deployment ptfconfig.

.DESCRIPTION
    Debug helper only; the test suite itself does not use it. Reads SutComputerName, SutUserName and SutPassword
    from MS-SMBD_ServerTestSuite.deployment.ptfconfig so no secret is stored in the script. Windows OpenSSH has no
    sshpass, so the password is handed to ssh through SSH_ASKPASS from a process-local environment variable.
    Failure to connect is not an error for the debugging workflow: the script prints the reason and exits non-zero.
    With -Sudo, the complete command (including redirections and pipelines) runs inside sudo sh -c.

.EXAMPLE
    .\Invoke-SutSsh.ps1 -Command "uname -r; systemctl is-active ksmbd"
    .\Invoke-SutSsh.ps1 -Sudo -Command "dmesg -T | grep -i ksmbd | tail -40"
    .\Invoke-SutSsh.ps1 -Sudo -Command "echo rdma > /sys/class/ksmbd-control/debug"   # toggles ksmbd rdma debug
#>
param(
    [Parameter(Mandatory)][string]$Command,
    [switch]$Sudo,
    [string]$Ptfconfig,
    [int]$ConnectTimeoutSec = 10
)

$ErrorActionPreference = 'Stop'
$sshExe = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
if (-not (Test-Path $sshExe)) { Write-Host "OpenSSH client not found at $sshExe"; exit 1 }

if (-not $Ptfconfig) {
    $candidates = @(
        (Join-Path $PSScriptRoot '..\..\TestSuite\bin\Debug\net8.0\MS-SMBD_ServerTestSuite.deployment.ptfconfig'),
        (Join-Path $PSScriptRoot '..\..\TestSuite\MS-SMBD_ServerTestSuite.deployment.ptfconfig'),
        (Join-Path $PSScriptRoot '..\..\Bin\MS-SMBD_ServerTestSuite.deployment.ptfconfig')
    )
    $Ptfconfig = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Ptfconfig) { Write-Host 'Deployment ptfconfig not found; pass -Ptfconfig.'; exit 1 }

# The ptfconfig is namespaced, so XPath on 'Property' does not work; use GetElementsByTagName.
[xml]$cfg = Get-Content $Ptfconfig
$props = @{}
foreach ($p in $cfg.GetElementsByTagName('Property')) { $props[$p.name] = $p.value }
$target = '{0}@{1}' -f $props['SutUserName'], $props['SutComputerName']
$password = $props['SutPassword']

if ($Sudo) {
    # -S reads the password from stdin; -p '' hides the prompt. Lab use only.
    $quotedCommand = "'" + $Command.Replace("'", "'\''") + "'"
    $quotedPassword = "'" + $password.Replace("'", "'\''") + "'"
    $Command = "printf '%s\n' $quotedPassword | sudo -S -p '' sh -c $quotedCommand"
}

$askpass = Join-Path $env:TEMP ('sut-askpass-{0}.cmd' -f $PID)
Set-Content -Path $askpass -Value '@echo %SUT_SSH_PASSWORD%' -Encoding ASCII
$env:SUT_SSH_PASSWORD = $password
$env:SSH_ASKPASS = $askpass
$env:SSH_ASKPASS_REQUIRE = 'force'
$env:DISPLAY = 'dummy'
try {
    & $sshExe -o "ConnectTimeout=$ConnectTimeoutSec" -o StrictHostKeyChecking=accept-new `
        -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 `
        $target $Command 2>&1
    exit $LASTEXITCODE
}
finally {
    Remove-Item $askpass -ErrorAction SilentlyContinue
    Remove-Item Env:\SUT_SSH_PASSWORD, Env:\SSH_ASKPASS, Env:\SSH_ASKPASS_REQUIRE -ErrorAction SilentlyContinue
}
