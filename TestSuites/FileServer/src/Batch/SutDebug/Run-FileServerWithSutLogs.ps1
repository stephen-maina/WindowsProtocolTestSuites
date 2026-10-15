<#
.SYNOPSIS
    Runs a FileServer test assembly against a Linux SUT (for example ksmbd) and collects the evidence needed to
    decide whether a failure is a product defect or a test that asserts Windows behaviour instead of the specification.

.DESCRIPTION
    Debug helper only; the test suites do not use it. For one run it produces, under -OutDir:
      results.trx           MSTest results (per-test start/end time, outcome, message)
      smb445.pcapng         wire trace of TCP port 445 on the driver (pktmon)
      sut-dmesg.log         full SUT kernel log (dmesg --time-format iso)
      tests\<name>.log      the dmesg lines that fall inside each test's start/end time
      summary.csv           outcome and first part of the failure message for every test
    The driver and SUT clocks must agree (the script prints both so a skew is visible). SUT access reuses
    Invoke-SutSsh.ps1 from the MS-SMBD suite, which reads the credentials from the MS-SMBD deployment ptfconfig.

.EXAMPLE
    .\Run-FileServerWithSutLogs.ps1 -TestDll ..\..\SMB2\TestSuite\bin\Debug\net8.0\MS-SMB2_ServerTestSuite.dll `
        -Filter "TestCategory=Bvt" -OutDir C:\FileServerRuns\bvt1
#>
param(
    [Parameter(Mandatory)][string]$TestDll,
    [string]$Filter = '',
    [Parameter(Mandatory)][string]$OutDir,
    [string]$SshScript = (Join-Path $PSScriptRoot '..\..\..\..\MS-SMBD\src\Batch\SutDebug\Invoke-SutSsh.ps1'),
    [int]$Port = 445
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir 'tests') | Out-Null
$TestDll = (Resolve-Path $TestDll).Path
$SshScript = (Resolve-Path $SshScript).Path

function Invoke-Sut([string]$Command, [switch]$Sudo) {
    if ($Sudo) { & $SshScript -Sudo -Command $Command } else { & $SshScript -Command $Command }
}

Write-Host ('Driver clock: ' + (Get-Date -Format o))
Write-Host ('SUT clock:    ' + ((Invoke-Sut 'date --iso-8601=seconds') | Select-Object -Last 1))

$etl = Join-Path $OutDir 'smb445.etl'
$captureStarted = $false
try {
    & pktmon stop 2>&1 | Out-Null
    & pktmon filter remove 2>&1 | Out-Null
    & pktmon filter add smb -p $Port 2>&1 | Out-Null
    & pktmon start --capture --comp nics --pkt-size 0 -f $etl 2>&1 | Out-Null
    $captureStarted = $true
} catch { Write-Warning "pktmon capture not started: $_" }

$runStart = Get-Date
Invoke-Sut 'echo WPTS-FS-RUN-BEGIN > /dev/kmsg' -Sudo | Out-Null

$trx = 'results.trx'
$dotnetArgs = @('test', $TestDll, '--no-build', '--logger', "trx;LogFileName=$trx", '--logger', 'console;verbosity=normal', '--results-directory', $OutDir)
if ($Filter) { $dotnetArgs += @('--filter', $Filter) }
& dotnet @dotnetArgs 2>&1 | Tee-Object -FilePath (Join-Path $OutDir 'console.log') | Select-String '^\s+(Passed|Failed|Skipped) |Passed!|Failed!'

Invoke-Sut 'echo WPTS-FS-RUN-END > /dev/kmsg' -Sudo | Out-Null
if ($captureStarted) {
    & pktmon stop 2>&1 | Out-Null
    & pktmon etl2pcap $etl -o (Join-Path $OutDir 'smb445.pcapng') 2>&1 | Out-Null
}

$dmesg = Invoke-Sut 'dmesg --time-format iso' -Sudo
$dmesg | Set-Content (Join-Path $OutDir 'sut-dmesg.log')

$entries = foreach ($line in $dmesg) {
    if ($line -match '^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)[,.](\d+)([+-]\d\d:\d\d)') {
        [pscustomobject]@{ Time = [datetimeoffset]::Parse($Matches[1] + '.' + $Matches[2].Substring(0, [Math]::Min(6, $Matches[2].Length)) + $Matches[3]); Line = $line }
    }
}

$x = [xml](Get-Content (Join-Path $OutDir $trx) -Raw)
$rows = foreach ($r in $x.TestRun.Results.UnitTestResult) {
    $msg = ''
    if ($r.Output -and $r.Output.ErrorInfo) { $msg = (($r.Output.ErrorInfo.Message -replace '\s+', ' ')).Trim() }
    if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
    $start = [datetimeoffset]::Parse($r.startTime); $end = [datetimeoffset]::Parse($r.endTime)
    $slice = @($entries | Where-Object { $_.Time -ge $start.AddSeconds(-1) -and $_.Time -le $end.AddSeconds(1) } | ForEach-Object { $_.Line })
    if ($slice.Count) { $slice | Set-Content (Join-Path $OutDir ('tests\' + $r.testName + '.log')) }
    [pscustomobject]@{ Test = $r.testName; Outcome = $r.outcome; Start = $start.ToString('o'); End = $end.ToString('o'); SutLines = $slice.Count; Message = $msg }
}
$rows | Export-Csv (Join-Path $OutDir 'summary.csv') -NoTypeInformation
$rows | Group-Object Outcome | ForEach-Object { '{0,5}  {1}' -f $_.Count, $_.Name }
Write-Host ('Run window: {0:o} .. {1:o}; output in {2}' -f $runStart, (Get-Date), $OutDir)
