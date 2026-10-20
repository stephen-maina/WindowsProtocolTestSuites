# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RepositoryPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ExpectedCommit,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResultsDirectory
)

$ErrorActionPreference = 'Stop'
$actualCommit = & git -C $RepositoryPath rev-parse HEAD
if ($LASTEXITCODE -ne 0) {
    throw "git rev-parse failed with exit code $LASTEXITCODE."
}
if ($actualCommit -ne $ExpectedCommit) {
    throw "Checked-out commit '$actualCommit' does not match '$ExpectedCommit'."
}

$projectRelativePath = 'TestSuites\MS-SMBD\src\Diagnostics.Tests\Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.csproj'
$project = Join-Path $RepositoryPath $projectRelativePath
if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
    throw "Diagnostics test project is missing at '$project'."
}

$reportPath = Join-Path $ResultsDirectory 'diagnostics.trx'
if (Test-Path -LiteralPath $reportPath) {
    throw "Results directory already contains diagnostics.trx; use a fresh directory."
}
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null

Write-Output "Executing diagnostics tests at verified commit $actualCommit."
& dotnet test $project --configuration Release --results-directory $ResultsDirectory --logger 'trx;LogFileName=diagnostics.trx'
if ($LASTEXITCODE -ne 0) {
    throw "dotnet test failed with exit code $LASTEXITCODE."
}
if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
    throw 'dotnet test did not produce diagnostics.trx.'
}

$report = [xml](Get-Content -LiteralPath $reportPath -Raw)
$counters = [ordered]@{}
foreach ($name in @('total', 'executed', 'passed', 'failed')) {
    $count = 0
    if (-not [int]::TryParse([string]$report.TestRun.ResultSummary.Counters.$name, [ref]$count) -or $count -lt 0) {
        throw "Native test report has an invalid '$name' counter."
    }
    $counters[$name] = $count
}
if ($counters.executed -eq 0) {
    throw 'Native test report contains no executed tests.'
}
if ($counters.failed -gt 0) {
    throw "Native test report contains $($counters.failed) failed tests."
}

[ordered]@{
    testedCommit = $actualCommit
    testProject = $projectRelativePath
    counters = $counters
} | ConvertTo-Json -Depth 3 |
    Set-Content -LiteralPath (Join-Path $ResultsDirectory 'diagnostics-ci.json') -Encoding UTF8
Write-Output "Diagnostics tests: executed=$($counters.executed), passed=$($counters.passed), failed=$($counters.failed)."
