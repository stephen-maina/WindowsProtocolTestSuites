# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.
<#
.SYNOPSIS
    Runs a command on the Windows SUT over WinRM, using an explicitly supplied credential.

.DESCRIPTION
    Debug helper only; the test suite itself does not use it. Reads SutComputerName
    from MS-SMBD_ServerTestSuite.deployment.ptfconfig, but does not use its username or password.
    Supply a PSCredential from Get-Credential or a secret store, with the intended DOMAIN\user or SUT\user account.
    Failure to connect is not an error for the debugging
    workflow: the script prints the reason and exits 1.

    Driver prerequisites: for an IP address or non-domain SUT, add the SUT to TrustedHosts (once, elevated):
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value <ip> -Concatenate -Force
    SUT prerequisites: Enable-PSRemoting, and the account is a local administrator.

.EXAMPLE
    $credential = Get-Credential
    .\Invoke-SutWinRM.ps1 -Credential $credential -Command "Get-SmbServerConfiguration | select EnableSMBDirect,EncryptData"
    .\Invoke-SutWinRM.ps1 -Credential $credential -Command "Get-NetAdapterRdma | ft Name,Enabled"
    .\Invoke-SutWinRM.ps1 -Credential $credential -Command "Get-WinEvent -LogName Microsoft-Windows-SMBServer/Operational -MaxEvents 30 | ft TimeCreated,Id,Message -Wrap"
    .\Invoke-SutWinRM.ps1 -Credential $credential -Command "Get-WinEvent -LogName Microsoft-Windows-SMBDirect/Admin -MaxEvents 30 | ft TimeCreated,Id,Message -Wrap"
#>
param(
    [Parameter(Mandatory)][string]$Command,
    [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential,
    [string]$Ptfconfig,
    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Stop'

if (-not $Ptfconfig) {
    $candidates = @(
        (Join-Path $PSScriptRoot '..\..\TestSuite\bin\Debug\net8.0\MS-SMBD_ServerTestSuite.deployment.ptfconfig'),
        (Join-Path $PSScriptRoot '..\..\TestSuite\MS-SMBD_ServerTestSuite.deployment.ptfconfig'),
        (Join-Path $PSScriptRoot '..\..\Bin\MS-SMBD_ServerTestSuite.deployment.ptfconfig')
    )
    $Ptfconfig = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Ptfconfig) { Write-Host 'Deployment ptfconfig not found; pass -Ptfconfig.'; exit 1 }

[xml]$cfg = Get-Content $Ptfconfig
$sutHost = $null
foreach ($p in $cfg.GetElementsByTagName('Property')) {
    if ($p.name -eq 'SutComputerName') { $sutHost = $p.value }
}
if ([string]::IsNullOrWhiteSpace($sutHost)) { Write-Host 'SutComputerName not found in deployment ptfconfig.'; exit 1 }

try {
    $opt = New-PSSessionOption -OperationTimeout ($TimeoutSec * 1000) -OpenTimeout ($TimeoutSec * 1000)
    Invoke-Command -ComputerName $sutHost -Credential $Credential -Authentication Negotiate -SessionOption $opt `
        -ScriptBlock ([scriptblock]::Create($Command)) | Out-String
}
catch {
    Write-Host "WinRM to $sutHost failed: $($_.Exception.Message)"
    exit 1
}
