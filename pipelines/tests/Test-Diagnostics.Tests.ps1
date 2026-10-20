# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

BeforeAll {
    $runner = Join-Path $PSScriptRoot '..\..\CommonScripts\Test-Diagnostics.ps1'
}

Describe 'Exact-commit diagnostics CI orchestration' {
    BeforeEach {
        $repository = Join-Path $TestDrive 'repository'
        $results = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $project = Join-Path $repository 'TestSuites\MS-SMBD\src\Diagnostics.Tests\Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.csproj'
        New-Item -ItemType Directory -Path (Split-Path $project) -Force | Out-Null
        New-Item -ItemType File -Path $project -Force | Out-Null
        $commit = '1111111111111111111111111111111111111111'
        Mock git {
            $global:LASTEXITCODE = 0
            '1111111111111111111111111111111111111111'
        }
        Mock dotnet {
            '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><ResultSummary><Counters total="3" executed="3" passed="3" failed="0"/></ResultSummary></TestRun>' |
                Set-Content -LiteralPath (Join-Path $results 'diagnostics.trx')
            $global:LASTEXITCODE = 0
        }
    }

    It 'executes the project and records the verified source and native counts' {
        & $runner -RepositoryPath $repository -ExpectedCommit $commit -ResultsDirectory $results

        Assert-MockCalled dotnet -Times 1 -Exactly
        $evidence = Get-Content -LiteralPath "$results\diagnostics-ci.json" -Raw | ConvertFrom-Json
        $evidence.testedCommit | Should -Be $commit
        $evidence.counters.executed | Should -Be 3
        $evidence.counters.failed | Should -Be 0
    }

    It 'rejects a different checkout before executing tests' {
        Mock git { $global:LASTEXITCODE = 0; '2222222222222222222222222222222222222222' }
        { & $runner -RepositoryPath $repository -ExpectedCommit $commit -ResultsDirectory $results } |
            Should -Throw '*does not match*'
        Assert-MockCalled dotnet -Times 0 -Exactly
    }

    It 'rejects injection-shaped commit data without invoking a command' {
        { & $runner -RepositoryPath $repository -ExpectedCommit "$commit; Write-Output injected" -ResultsDirectory $results } |
            Should -Throw '*ExpectedCommit*'
        Assert-MockCalled git -Times 0 -Exactly
        Assert-MockCalled dotnet -Times 0 -Exactly
    }

    It 'surfaces a Git failure before executing tests' {
        Mock git { $global:LASTEXITCODE = 7 }
        { & $runner -RepositoryPath $repository -ExpectedCommit $commit -ResultsDirectory $results } |
            Should -Throw '*git rev-parse failed*'
        Assert-MockCalled dotnet -Times 0 -Exactly
    }

    It 'rejects a source without the standalone diagnostics project' {
        Remove-Item -LiteralPath $project
        { & $runner -RepositoryPath $repository -ExpectedCommit $commit -ResultsDirectory $results } |
            Should -Throw '*Diagnostics test project is missing*'
        Assert-MockCalled dotnet -Times 0 -Exactly
    }

    It 'surfaces a nonzero test runner exit code' {
        Mock dotnet { $global:LASTEXITCODE = 5 }
        { & $runner -RepositoryPath $repository -ExpectedCommit $commit -ResultsDirectory $results } |
            Should -Throw '*dotnet test failed with exit code 5*'
        Test-Path -LiteralPath "$results\diagnostics-ci.json" | Should -Be $false
    }

    It 'does not accept success without a native test report' {
        Mock dotnet { $global:LASTEXITCODE = 0 }
        { & $runner -RepositoryPath $repository -ExpectedCommit $commit -ResultsDirectory $results } |
            Should -Throw '*did not produce diagnostics.trx*'
    }

    It 'does not accept a report with zero executed tests' {
        Mock dotnet {
            '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><ResultSummary><Counters total="0" executed="0" passed="0" failed="0"/></ResultSummary></TestRun>' |
                Set-Content -LiteralPath (Join-Path $results 'diagnostics.trx')
            $global:LASTEXITCODE = 0
        }
        { & $runner -RepositoryPath $repository -ExpectedCommit $commit -ResultsDirectory $results } |
            Should -Throw '*no executed tests*'
    }

    It 'rejects invalid native counters rather than treating them as zero' {
        Mock dotnet {
            '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><ResultSummary><Counters total="3" executed="3" passed="3" failed="invalid"/></ResultSummary></TestRun>' |
                Set-Content -LiteralPath (Join-Path $results 'diagnostics.trx')
            $global:LASTEXITCODE = 0
        }
        { & $runner -RepositoryPath $repository -ExpectedCommit $commit -ResultsDirectory $results } |
            Should -Throw "*invalid 'failed' counter*"
    }

    It 'rejects reported failures even when the native command returns zero' {
        Mock dotnet {
            '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><ResultSummary><Counters total="3" executed="3" passed="2" failed="1"/></ResultSummary></TestRun>' |
                Set-Content -LiteralPath (Join-Path $results 'diagnostics.trx')
            $global:LASTEXITCODE = 0
        }
        { & $runner -RepositoryPath $repository -ExpectedCommit $commit -ResultsDirectory $results } |
            Should -Throw '*contains 1 failed tests*'
        Test-Path -LiteralPath "$results\diagnostics-ci.json" | Should -Be $false
    }

    It 'refuses to reuse a stale report on replay' {
        New-Item -ItemType Directory -Path $results -Force | Out-Null
        '<TestRun/>' | Set-Content -LiteralPath "$results\diagnostics.trx"
        { & $runner -RepositoryPath $repository -ExpectedCommit $commit -ResultsDirectory $results } |
            Should -Throw '*already contains diagnostics.trx*'
        Assert-MockCalled dotnet -Times 0 -Exactly
    }
}
