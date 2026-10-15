// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading;
using Microsoft.Protocols.TestSuites.Diagnostics.Lifecycle;
using Microsoft.Protocols.TestSuites.Diagnostics.Runner;
using Microsoft.Protocols.TestSuites.Diagnostics.Sut;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.Logging;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Ptf;

/// <summary>
/// WHAT: One per-test object that owns the shared diagnostics for a PTF test: the invocation lifecycle (artifact
/// folder, capture provider) and the SUT log window (<see cref="SutLogCollector"/>).
/// WHY: Every suite's test base needs the same four calls (start, end, mark cleanup, dispose). Keeping them here
/// means a suite adopts diagnostics with a few lines instead of copying the wiring.
/// SPEC: Not protocol behaviour; debugging aid only. It is best-effort and must never fail a test.
/// </summary>
public sealed class PtfTestDiagnostics : IDisposable
{
    private readonly ITestSite site;
    private readonly PtfDiagnosticsSuite suite;
    private DiagnosticsInvocationLifecycle? lifecycle;
    private SutLogCollector? sutLogCollector;

    private PtfTestDiagnostics(ITestSite site, PtfDiagnosticsSuite suite)
    {
        this.site = site;
        this.suite = suite;
    }

    public DiagnosticsInvocationLifecycle? Lifecycle => lifecycle;

    /// <param name="managedType">TestContext.ManagedType, when available.</param>
    /// <param name="managedMethod">TestContext.ManagedMethod, when available.</param>
    /// <param name="displayName">TestContext.TestDisplayName or TestName, when available.</param>
    /// <param name="runCount">TestContext.TestRunCount, when available.</param>
    public static PtfTestDiagnostics Begin(
        ITestSite site,
        PtfDiagnosticsSuite suite,
        string buildOutputRoot,
        SutLogCollector.PropertyNames? sutPropertyNames = null,
        string? managedType = null,
        string? managedMethod = null,
        string? displayName = null,
        int? runCount = null)
    {
        var diagnostics = new PtfTestDiagnostics(site, suite);
        diagnostics.lifecycle = PtfDiagnosticsLifecycle.Start(
            suite.Flatten(site.Properties),
            site.TestProperties,
            site.Log,
            buildOutputRoot,
            suite,
            () => CreateRunnerIdentity(site, managedType, managedMethod, displayName, runCount));
        diagnostics.sutLogCollector = SutLogCollector.Create(
            suite.Flatten(site.Properties),
            site.TestProperties.TryGetValue("CurrentTestCaseName", out object? name) ? name as string : null,
            sutPropertyNames);
        diagnostics.sutLogCollector?.Begin();
        return diagnostics;
    }

    /// <summary>
    /// Closes the SUT log window, stores it next to the test's other artifacts and records cleanup state.
    /// </summary>
    public void End(bool cleanupCompleted)
    {
        try
        {
            sutLogCollector?.EndAndSave(lifecycle?.ArtifactDirectoryPath);
        }
        catch
        {
        }

        if (cleanupCompleted)
        {
            lifecycle?.MarkCleanupCompleted();
        }
        else
        {
            lifecycle?.MarkCleanupFailed();
        }
    }

    public void Dispose()
    {
        DiagnosticsInvocationLifecycle? current = Interlocked.Exchange(ref lifecycle, null);
        if (current == null)
        {
            return;
        }

        current.Dispose();
        foreach (var error in current.Errors.Chronology)
        {
            site.Log.Add(
                LogEntryKind.Warning,
                "{0} diagnostics {1}: {2}",
                suite.Name,
                error.Code,
                error.Message);
        }
    }

    private static RunnerTestExecutionIdentity CreateRunnerIdentity(
        ITestSite site,
        string? managedType,
        string? managedMethod,
        string? displayName,
        int? runCount)
    {
        string current = (string)site.TestProperties["CurrentTestCaseName"];
        int separator = current.LastIndexOf('.');
        string fallbackType = separator > 0 ? current[..separator] : current;
        string fallbackMethod = separator > 0 ? current[(separator + 1)..] : current;
        return new RunnerTestExecutionIdentity(
            managedType ?? fallbackType,
            managedMethod ?? fallbackMethod,
            displayName ?? current,
            runCount ?? 0);
    }
}
