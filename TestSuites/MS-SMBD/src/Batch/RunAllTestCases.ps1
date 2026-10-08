# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

param(
    [switch]$DryRun = $false # If set, just list all test cases instead of running tests actually.
)

$invocationPath =  Split-Path $MyInvocation.MyCommand.Definition -Parent

$script = Join-Path $invocationPath "RunTestCasesByFilter.ps1"

& $script -DryRun:$DryRun.IsPresent

# Propagate only the managed diagnostics runner result through this outer wrapper.
if ($null -ne $global:__SmbdDiagnosticsManagedRunnerExitCode)
{
    exit [int]$global:__SmbdDiagnosticsManagedRunnerExitCode
}
