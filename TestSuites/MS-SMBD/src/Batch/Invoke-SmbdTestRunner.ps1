# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

param(
    [array]$Binaries,
    [string]$Filter = "",
    [switch]$DryRun = $false
)

$global:__SmbdDiagnosticsManagedRunnerExitCode = $null

$invocationPath = Split-Path $MyInvocation.MyCommand.Definition -Parent
$rootPath = Split-Path $invocationPath -Parent
$binPath = Join-Path $rootPath "Bin"
$canonicalConfig = Join-Path $binPath "MS-SMBD_ServerTestSuite.ptfconfig"
$deploymentConfig = Join-Path $binPath "MS-SMBD_ServerTestSuite.deployment.ptfconfig"
$fallbackRunner = Join-Path $invocationPath "RunTestCasesByBinariesAndFilter.ps1"

function Test-SmbdDiagnosticsEnabled {
    param([string]$ConfigurationPath)

    if (-not (Test-Path -LiteralPath $ConfigurationPath -PathType Leaf)) {
        return $false
    }

    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.IgnoreComments = $true
    $settings.IgnoreWhitespace = $true
    $settings.MaxCharactersInDocument = 16MB
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create($ConfigurationPath, $settings)
    try {
        while ($reader.Read()) {
            if ($reader.NodeType -ne [System.Xml.XmlNodeType]::Element -or
                $reader.LocalName -cne "Property" -or
                $reader.NamespaceURI -cne "http://schemas.microsoft.com/windows/ProtocolsTest/2007/07/TestConfig" -or
                $reader.GetAttribute("name") -cne "Diagnostics.Enabled") {
                continue
            }

            $enabled = $false
            $raw = $reader.GetAttribute("value")
            if ([string]::IsNullOrEmpty($raw)) {
                return $false
            }

            if ([bool]::TryParse($raw.Trim(), [ref]$enabled)) {
                return $enabled
            }

            return $false
        }

        return $false
    }
    finally {
        $reader.Dispose()
    }
}

$diagnosticsEnabled = $false
if (-not $DryRun) {
    try {
        $diagnosticsEnabled = Test-SmbdDiagnosticsEnabled $canonicalConfig
    }
    catch {
        Write-Warning "MS-SMBD diagnostics policy could not be read; continuing without runner evidence."
    }
}

if ($DryRun -or -not $diagnosticsEnabled) {
    & $fallbackRunner `
        -Binaries $Binaries `
        -Filter $Filter `
        -DryRun:$DryRun.IsPresent
    return
}

$runnerAssembly = Join-Path $binPath "Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Runner.dll"
if (-not (Test-Path -LiteralPath $runnerAssembly -PathType Leaf)) {
    Write-Warning "The packaged MS-SMBD diagnostics runner is unavailable; continuing without runner evidence."
    & $fallbackRunner `
        -Binaries $Binaries `
        -Filter $Filter `
        -DryRun:$false
    return
}

$runnerArguments = @(
    $runnerAssembly,
    "run",
    "--config",
    $canonicalConfig,
    "--deployment-config",
    $deploymentConfig
)

foreach ($binary in $Binaries) {
    $runnerArguments += "--binary"
    $runnerArguments += (Join-Path $binPath $binary)
}

if (-not [string]::IsNullOrEmpty($Filter)) {
    $runnerArguments += "--filter"
    $runnerArguments += $Filter
}

& dotnet @runnerArguments
$global:__SmbdDiagnosticsManagedRunnerExitCode = $LASTEXITCODE
exit $global:__SmbdDiagnosticsManagedRunnerExitCode
