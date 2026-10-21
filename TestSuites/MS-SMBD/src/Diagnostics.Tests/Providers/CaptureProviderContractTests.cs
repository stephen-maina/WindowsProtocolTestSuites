// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Providers;

[TestClass]
public sealed class CaptureProviderContractTests
{
    private static readonly CaptureProviderTimeouts ShortTimeouts =
        new(
            TimeSpan.FromMilliseconds(250),
            TimeSpan.FromMilliseconds(250),
            TimeSpan.FromMilliseconds(250));

    private static readonly CaptureProviderTimeouts BoundedTimeouts =
        new(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));

    [DataTestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task CompleteAsync_AuxiliaryUnresolvedOrThrowing_AlwaysStopsPrimaryAndAbandonsWriter(bool throws)
    {
            using ProviderTestContext context = ProviderTestContext.Create();
            var primary = new DeterministicCaptureProvider();
            var auxiliary = new DeterministicCaptureProvider
            {
                RequestStopAsyncHandler = (_, _) => throws
                    ? throw new InvalidOperationException("hostile secret")
                    : Task.FromResult(CaptureProviderStopResult.Failed(
                        false, CaptureProviderFailureCode.StopTimeout, "Still active.")),
            };
            var errors = new DiagnosticErrorLedger();
            CaptureProviderSession session = await CaptureProviderOrchestrator.CreateEnabled(errors)
                .StartAsync(() => context.Request,
                    () => new AuxiliaryCaptureProvider(primary, auxiliary),
                    BoundedTimeouts, CancellationToken.None);

            CaptureProviderCompletionResult completion =
                await session.CompleteAsync(BoundedTimeouts, CancellationToken.None);

            Assert.AreEqual(CaptureProviderLifecycleState.Abandoned, completion.State);
            Assert.IsFalse(completion.WriterResolved);
            Assert.AreEqual(throws ? CaptureProviderFailureCode.StopFailed :
                CaptureProviderFailureCode.StopTimeout, completion.FailureCode);
            Assert.AreEqual(1, primary.Calls.Count(call => call == "Stop"));
            Assert.AreEqual(1, auxiliary.Calls.Count(call => call == "Stop"));
            Assert.IsFalse(primary.Calls.Contains("Finalization"));
            Assert.IsFalse(errors.Chronology.Any(error => error.Message.Contains("hostile")));
    }

    [TestMethod]
    public async Task FinalizeAsync_AuxiliaryStopUnresolved_DoesNotReturnPrimarySuccess()
    {
        using ProviderTestContext context = ProviderTestContext.Create();
        var primary = new DeterministicCaptureProvider();
        var auxiliary = new DeterministicCaptureProvider
        {
            RequestStopAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderStopResult.Failed(false, CaptureProviderFailureCode.StopFailed, "Unresolved.")),
        };
        var composite = new AuxiliaryCaptureProvider(primary, auxiliary);
        CaptureProviderStartResult start = await composite.StartAsync(context.Request, CancellationToken.None);

        CaptureProviderStopResult stop = await composite.RequestStopAsync(start.Handle!, CancellationToken.None);
        CaptureProviderFinalizationResult finalization =
            await composite.WaitForFinalizationAsync(start.Handle!, CancellationToken.None);

        Assert.IsFalse(stop.WriterResolved);
        Assert.AreEqual(CaptureProviderFinalizationStatus.Failed, finalization.Status);
        Assert.AreEqual(CaptureProviderFailureCode.FinalizationFailed, finalization.FailureCode);
        Assert.AreEqual(1, primary.Calls.Count(call => call == "Stop"));
        Assert.IsFalse(auxiliary.Calls.Contains("Finalization"));
    }

    [DataTestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task CompleteAsync_AuxiliaryUnavailableOrStopped_CompletesWithResolvedWriter(bool unavailable)
    {
        using ProviderTestContext context = ProviderTestContext.Create();
        var primary = new DeterministicCaptureProvider();
        var auxiliary = new DeterministicCaptureProvider();
        if (unavailable)
        {
            auxiliary.ProbeAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderProbeResult.Unavailable(CaptureProviderFailureCode.ToolMissing, "Absent."));
        }
        var errors = new DiagnosticErrorLedger();
        CaptureProviderSession session = await CaptureProviderOrchestrator.CreateEnabled(errors)
            .StartAsync(() => context.Request,
                () => new AuxiliaryCaptureProvider(primary, auxiliary),
                BoundedTimeouts, CancellationToken.None);

        CaptureProviderCompletionResult completion =
            await session.CompleteAsync(BoundedTimeouts, CancellationToken.None);

        Assert.AreEqual(CaptureProviderLifecycleState.Completed, completion.State);
        Assert.IsTrue(completion.WriterResolved);
        Assert.AreEqual(1, primary.Calls.Count(call => call == "Stop"));
        Assert.AreEqual(1, primary.Calls.Count(call => call == "Finalization"));
        Assert.AreEqual(unavailable ? 0 : 1, auxiliary.Calls.Count(call => call == "Stop"));
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public async Task StartAsync_Disabled_DoesNotCreateRequestOrProvider_Issue64410325()
    {
        // Arrange
        int requestFactoryCalls = 0;
        int providerFactoryCalls = 0;
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateDisabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () =>
            {
                requestFactoryCalls++;
                throw new InvalidOperationException("The disabled request factory must not run.");
            },
            () =>
            {
                providerFactoryCalls++;
                throw new InvalidOperationException("The disabled provider factory must not run.");
            },
            BoundedTimeouts,
            CancellationToken.None);
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Disabled, session.State);
        Assert.AreEqual(CaptureProviderLifecycleState.Disabled, completion.State);
        Assert.AreEqual(0, requestFactoryCalls);
        Assert.AreEqual(0, providerFactoryCalls);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public async Task StartAndCompleteAsync_Success_UsesOrderedOwnedLifecycle_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider();
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        CollectionAssert.AreEqual(
            new[] { "Probe", "Start", "Readiness", "Stop", "Finalization" },
            provider.Calls.ToArray());
        Assert.AreEqual(CaptureProviderReadinessStatus.Ready, session.ReadinessStatus);
        Assert.AreEqual(CaptureProviderLifecycleState.Completed, completion.State);
        Assert.AreEqual(CaptureProviderStopStatus.Stopped, completion.StopStatus);
        Assert.AreEqual(
            CaptureProviderFinalizationStatus.Finalized,
            completion.FinalizationStatus);
        CollectionAssert.AreEqual(
            new[]
            {
                CaptureProviderLifecycleState.Allocated,
                CaptureProviderLifecycleState.Starting,
                CaptureProviderLifecycleState.Capturing,
                CaptureProviderLifecycleState.Stopping,
                CaptureProviderLifecycleState.Finalizing,
                CaptureProviderLifecycleState.Completed,
            },
            session.StateHistory.ToArray());
        Assert.AreEqual(
            CoverageQualification.Unverified,
            session.Capabilities?.Qualification);
        Assert.AreEqual("Deterministic graceful stop.", completion.StopDetail);
        Assert.AreEqual(
            "Deterministic finalization evidence.",
            completion.FinalizationDetail);
        Assert.AreEqual(0, completion.Artifacts.Count);
        Assert.IsTrue(completion.WriterResolved);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public async Task StartAndCompleteAsync_ProviderIdThrowsAfterFirstRead_UsesCachedIdentityAndPreservesProtocolError_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            ProviderIdReadHandler = static readCount =>
                readCount == 1
                    ? "deterministic"
                    : throw new InvalidOperationException(
                        "ProviderId must not be read more than once."),
        };
        var errors = new DiagnosticErrorLedger();
        errors.RecordProtocolError(
            "ProtocolAssertionFailed",
            "The protocol assertion failed.",
            DateTimeOffset.Parse("2026-10-02T16:00:00Z"));
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(1, provider.ProviderIdReadCount);
        Assert.AreEqual(CaptureProviderLifecycleState.Completed, completion.State);
        Assert.IsTrue(completion.WriterResolved);
        CollectionAssert.AreEqual(
            new[] { "Probe", "Start", "Readiness", "Stop", "Finalization" },
            provider.Calls.ToArray());
        Assert.AreEqual("ProtocolAssertionFailed", errors.PrimaryProtocolError?.Code);
        CollectionAssert.AreEqual(
            new[] { "ProtocolAssertionFailed" },
            errors.Chronology.Select(error => error.Code).ToArray());
    }

    [TestMethod]
    public async Task StartAsync_FirstProviderIdReadThrows_ClassifiesCreationFailure_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            ProviderIdReadHandler = static _ =>
                throw new InvalidOperationException("Provider identity is unavailable."),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(1, provider.ProviderIdReadCount);
        Assert.AreEqual(CaptureProviderLifecycleState.Unavailable, session.State);
        Assert.AreEqual(
            CaptureProviderFailureCode.ProviderCreationFailed,
            session.StartupFailureCode);
        Assert.AreEqual(0, provider.Calls.Count);
        Assert.AreEqual("ProviderCreationFailed", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task StartAsync_ForeignOwnerHandle_RejectsHandleWithoutStoppingIt_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            StartAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderStartResult.Started(
                    CaptureProviderSessionHandle.Create(
                        "deterministic",
                        "another-invocation",
                        "foreign-session"))),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);
        CaptureProviderLifecycleState startupState = session.State;
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        CollectionAssert.AreEqual(new[] { "Probe", "Start" }, provider.Calls.ToArray());
        Assert.AreEqual(CaptureProviderLifecycleState.Unavailable, startupState);
        Assert.AreEqual(CaptureProviderFailureCode.OwnershipMismatch, session.StartupFailureCode);
        Assert.AreEqual(CaptureProviderLifecycleState.Abandoned, completion.State);
        Assert.IsFalse(completion.WriterResolved);
        Assert.AreEqual("OwnershipMismatch", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task StartAsync_ProbeUnavailable_ClassifiesFailureWithoutStarting_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            ProbeAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderProbeResult.Unavailable(
                    CaptureProviderFailureCode.ToolMissing,
                    "The controlled provider executable is absent.")),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        CollectionAssert.AreEqual(new[] { "Probe" }, provider.Calls.ToArray());
        Assert.AreEqual(CaptureProviderLifecycleState.Unavailable, session.State);
        Assert.AreEqual(CaptureProviderFailureCode.ToolMissing, session.StartupFailureCode);
        Assert.AreEqual(DiagnosticErrorCategory.Capture, errors.Chronology.Single().Category);
        Assert.AreEqual("ToolMissing", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task StartAsync_StartFailure_ClassifiesFailureWithoutReadiness_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            StartAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderStartResult.Failed(
                    CaptureProviderFailureCode.CaptureBusy,
                    "The controlled target is busy.")),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        CollectionAssert.AreEqual(new[] { "Probe", "Start" }, provider.Calls.ToArray());
        Assert.AreEqual(CaptureProviderFailureCode.CaptureBusy, session.StartupFailureCode);
        Assert.AreEqual("CaptureBusy", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task StartAsync_StartFailureWithOwnedHandle_CleansPartialInitialization_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            StartAsyncHandler = static (request, _) => Task.FromResult(
                CaptureProviderStartResult.FailedWithOwnedHandle(
                    CaptureProviderSessionHandle.Create(
                        "deterministic",
                        request.Identity.InvocationId,
                        "partial-session"),
                    CaptureProviderFailureCode.StartFailed,
                    "The controlled start failed after allocating an owned session.")),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Unavailable, session.StateHistory[2]);
        Assert.AreEqual(CaptureProviderFailureCode.StartFailed, session.StartupFailureCode);
        CollectionAssert.AreEqual(
            new[] { "Probe", "Start", "Stop", "Finalization" },
            provider.Calls.ToArray());
        Assert.AreEqual(CaptureProviderLifecycleState.Completed, completion.State);
        Assert.IsTrue(completion.WriterResolved);
        Assert.AreEqual("StartFailed", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task StartAsync_StartOperationTimesOut_ReportsPotentialWriterUnresolved_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var startSource = new TaskCompletionSource<CaptureProviderStartResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var provider = new DeterministicCaptureProvider
        {
            StartAsyncHandler = (_, _) => startSource.Task,
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            ShortTimeouts,
            CancellationToken.None);
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderFailureCode.StartTimeout, session.StartupFailureCode);
        Assert.AreEqual(CaptureProviderLifecycleState.Abandoned, completion.State);
        Assert.IsFalse(completion.WriterResolved);
        CollectionAssert.AreEqual(new[] { "Probe", "Start" }, provider.Calls.ToArray());
        Assert.AreEqual("StartTimeout", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task StartAsync_NullProbeResult_ClassifiesProviderContractFailure_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            ProbeAsyncHandler = static (_, _) =>
                Task.FromResult<CaptureProviderProbeResult>(null!),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Unavailable, session.State);
        Assert.AreEqual(CaptureProviderFailureCode.ProbeFailed, session.StartupFailureCode);
        Assert.AreEqual("ProbeFailed", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task StartAsync_ReadinessUnverified_KeepsOwnedSessionWithoutClaimingReady_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            WaitForReadinessAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderReadinessResult.Unverified(
                    "The controlled provider has no qualified readiness signal.")),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);
        CaptureProviderLifecycleState startupState = session.State;
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Capturing, startupState);
        Assert.AreEqual(
            CaptureProviderReadinessStatus.Unverified,
            session.ReadinessStatus);
        Assert.AreEqual(
            CaptureProviderFailureCode.ReadinessUnverified,
            session.StartupFailureCode);
        Assert.AreEqual(CaptureProviderLifecycleState.Completed, completion.State);
        Assert.AreEqual("ReadinessUnverified", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task StartAsync_ReadinessNeverCompletes_TimesOutWithoutFalseReadiness_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var readiness = new TaskCompletionSource<CaptureProviderReadinessResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var provider = new DeterministicCaptureProvider
        {
            WaitForReadinessAsyncHandler = (_, _) => readiness.Task,
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            ShortTimeouts,
            CancellationToken.None);
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderReadinessStatus.TimedOut, session.ReadinessStatus);
        Assert.AreEqual(CaptureProviderFailureCode.StartTimeout, session.StartupFailureCode);
        CollectionAssert.AreEqual(
            new[] { "Probe", "Start", "Readiness", "Stop", "Finalization" },
            provider.Calls.ToArray());
        Assert.AreEqual(CaptureProviderLifecycleState.Completed, completion.State);
    }

    [TestMethod]
    public async Task StartAsync_CancelledBeforeWork_DoesNotCreateRequestOrProvider_Issue64410325()
    {
        // Arrange
        int requestFactoryCalls = 0;
        int providerFactoryCalls = 0;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);

        // Act
        CaptureProviderSession session = await orchestrator.StartAsync(
            () =>
            {
                requestFactoryCalls++;
                throw new InvalidOperationException("A cancelled start must not create a request.");
            },
            () =>
            {
                providerFactoryCalls++;
                throw new InvalidOperationException("A cancelled start must not create a provider.");
            },
            BoundedTimeouts,
            cancellation.Token);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Unavailable, session.State);
        Assert.AreEqual(CaptureProviderFailureCode.Cancelled, session.StartupFailureCode);
        Assert.AreEqual(0, requestFactoryCalls);
        Assert.AreEqual(0, providerFactoryCalls);
        Assert.AreEqual("Cancelled", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task CompleteAsync_RepeatedCalls_StopAndFinalizeOnce_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider();
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        CaptureProviderCompletionResult first = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);
        CaptureProviderCompletionResult second = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreSame(first, second);
        Assert.AreEqual(1, provider.Calls.Count(call => call == "Stop"));
        Assert.AreEqual(1, provider.Calls.Count(call => call == "Finalization"));
    }

    [TestMethod]
    public async Task ObserveHealthAsync_ExitedEarly_ClassifiesFailureWithoutBlockingOwnedCleanup_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            ObserveHealthAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderHealthResult.ExitedEarly(
                    "The controlled capture exited before cleanup.")),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        CaptureProviderHealthResult health = await session.ObserveHealthAsync(
            BoundedTimeouts.StartTimeout,
            CancellationToken.None);
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderHealthStatus.ExitedEarly, health.Status);
        Assert.AreEqual(CaptureProviderFailureCode.ExitedEarly, health.FailureCode);
        Assert.AreEqual(CaptureProviderLifecycleState.Completed, completion.State);
        CollectionAssert.AreEqual(
            new[] { "Probe", "Start", "Readiness", "Health", "Stop", "Finalization" },
            provider.Calls.ToArray());
        Assert.AreEqual("ExitedEarly", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task ObserveHealthAsync_Disabled_ReturnsDisabledWithoutSideEffects_Issue64410325()
    {
        // Arrange
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator =
            CaptureProviderOrchestrator.CreateDisabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => throw new InvalidOperationException("Disabled request must not be created."),
            () => throw new InvalidOperationException("Disabled provider must not be created."),
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        CaptureProviderHealthResult health = await session.ObserveHealthAsync(
            BoundedTimeouts.StartTimeout,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderHealthStatus.Disabled, health.Status);
        Assert.AreEqual(CaptureProviderFailureCode.None, health.FailureCode);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public async Task ObserveHealthAsync_OperationNeverCompletes_ReturnsBoundedTimeout_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var healthSource = new TaskCompletionSource<CaptureProviderHealthResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var provider = new DeterministicCaptureProvider
        {
            ObserveHealthAsyncHandler = (_, _) => healthSource.Task,
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        CaptureProviderHealthResult health = await session.ObserveHealthAsync(
            TimeSpan.Zero,
            CancellationToken.None);
        await session.CompleteAsync(BoundedTimeouts, CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderHealthStatus.TimedOut, health.Status);
        Assert.AreEqual(CaptureProviderFailureCode.HealthTimeout, health.FailureCode);
        Assert.AreEqual("HealthTimeout", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task ObserveHealthAsync_AfterCompletion_DoesNotReenterFinalizedProvider_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider();
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);
        await session.CompleteAsync(BoundedTimeouts, CancellationToken.None);

        // Act
        CaptureProviderHealthResult health = await session.ObserveHealthAsync(
            BoundedTimeouts.StartTimeout,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderHealthStatus.Failed, health.Status);
        Assert.AreEqual(CaptureProviderFailureCode.HealthFailed, health.FailureCode);
        Assert.AreEqual(0, provider.Calls.Count(call => call == "Health"));
        Assert.AreEqual("HealthFailed", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task CompleteAsync_StopNeverCompletes_LeavesWriterUnresolvedAndSkipsFinalization_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var stop = new TaskCompletionSource<CaptureProviderStopResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var provider = new DeterministicCaptureProvider
        {
            RequestStopAsyncHandler = (_, _) => stop.Task,
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            ShortTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Abandoned, completion.State);
        Assert.AreEqual(CaptureProviderFailureCode.StopTimeout, completion.FailureCode);
        Assert.IsFalse(completion.WriterResolved);
        Assert.IsFalse(provider.Calls.Contains("Finalization"));
        Assert.AreEqual(DiagnosticErrorCategory.Cleanup, errors.Chronology.Single().Category);
        Assert.AreEqual("StopTimeout", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task CompleteAsync_SynchronousStopPrologueBlocks_ReturnsBoundedAndKeepsStateReadable_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        using var stopEntered = new ManualResetEventSlim();
        using var releaseStop = new ManualResetEventSlim();
        using var cancellationEntered = new ManualResetEventSlim();
        using var releaseCancellation = new ManualResetEventSlim();
        var provider = new DeterministicCaptureProvider
        {
            RequestStopAsyncHandler = (_, cancellationToken) =>
            {
                using CancellationTokenRegistration registration =
                    cancellationToken.Register(
                    () =>
                    {
                        cancellationEntered.Set();
                        releaseCancellation.Wait();
                    });
                stopEntered.Set();
                releaseStop.Wait();
                throw new InvalidOperationException(
                    "The late stop failure must be observed and contained.");
            },
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);
        var shortTimeouts = new CaptureProviderTimeouts(
            TimeSpan.FromSeconds(5),
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(5));

        // Act
        Task<Task<CaptureProviderCompletionResult>> invocationTask =
            Task.Factory.StartNew(
                () => session.CompleteAsync(shortTimeouts, CancellationToken.None),
                CancellationToken.None,
                TaskCreationOptions.DenyChildAttach,
                TaskScheduler.Default);
        Assert.IsTrue(
            stopEntered.Wait(TimeSpan.FromSeconds(2)),
            "The deterministic stop prologue did not start.");

        bool completeAsyncReturnedWithinBound;
        bool stateReadableWithinBound;
        CaptureProviderCompletionResult? completion = null;
        CaptureProviderLifecycleState? observedState = null;
        Task<CaptureProviderLifecycleState> stateRead = Task.Run(() => session.State);
        try
        {
            completeAsyncReturnedWithinBound =
                await Task.WhenAny(invocationTask, Task.Delay(TimeSpan.FromSeconds(1))) ==
                invocationTask;
            stateReadableWithinBound =
                await Task.WhenAny(stateRead, Task.Delay(TimeSpan.FromSeconds(1))) ==
                stateRead;
            if (stateReadableWithinBound)
            {
                observedState = await stateRead;
            }

            if (completeAsyncReturnedWithinBound)
            {
                Task<CaptureProviderCompletionResult> boundedCompletion =
                    await invocationTask;
                completion = await boundedCompletion.WaitAsync(TimeSpan.FromSeconds(2));
                Assert.IsTrue(
                    cancellationEntered.Wait(TimeSpan.FromSeconds(1)),
                    "Timeout cancellation was not signaled to the provider.");
            }
        }
        finally
        {
            releaseStop.Set();
            releaseCancellation.Set();
        }

        Task<CaptureProviderCompletionResult> completionTask =
            await invocationTask.WaitAsync(TimeSpan.FromSeconds(2));
        completion ??= await completionTask.WaitAsync(TimeSpan.FromSeconds(2));
        observedState ??= await stateRead.WaitAsync(TimeSpan.FromSeconds(2));

        // Assert
        Assert.IsTrue(
            completeAsyncReturnedWithinBound,
            "CompleteAsync must release the session lock immediately.");
        Assert.IsTrue(
            stateReadableWithinBound,
            "Session state must remain concurrently readable during a provider prologue.");
        Assert.AreEqual(CaptureProviderLifecycleState.Stopping, observedState.Value);
        Assert.AreEqual(CaptureProviderLifecycleState.Abandoned, completion.State);
        Assert.AreEqual(CaptureProviderFailureCode.StopTimeout, completion.FailureCode);
        Assert.AreEqual("StopTimeout", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task CompleteAsync_ForcedStop_IsRecordedAndFinalizedOnlyWhenWriterResolved_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            RequestStopAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderStopResult.Forced(
                    writerResolved: true,
                    "The controlled provider required forced stop.")),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderStopStatus.Forced, completion.StopStatus);
        Assert.AreEqual(CaptureProviderLifecycleState.Completed, completion.State);
        Assert.AreEqual(CaptureProviderFailureCode.ForcedStop, completion.FailureCode);
        Assert.AreEqual("ForcedStop", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task CompleteAsync_StopFailureWithUnresolvedWriter_DoesNotFinalize_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            RequestStopAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderStopResult.Failed(
                    writerResolved: false,
                    CaptureProviderFailureCode.StopFailed,
                    "The controlled writer may still be active.")),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Abandoned, completion.State);
        Assert.IsFalse(completion.WriterResolved);
        Assert.IsFalse(provider.Calls.Contains("Finalization"));
        Assert.AreEqual("StopFailed", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task CompleteAsync_FinalizationFailure_ClassifiesIndependentlyAfterWriterStops_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            WaitForFinalizationAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderFinalizationResult.Failed(
                    CaptureProviderFailureCode.FinalizationFailed,
                    "The controlled artifact could not be finalized.")),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Failed, completion.State);
        Assert.AreEqual(
            CaptureProviderFinalizationStatus.Failed,
            completion.FinalizationStatus);
        Assert.AreEqual(
            CaptureProviderFailureCode.FinalizationFailed,
            completion.FailureCode);
        Assert.IsTrue(completion.WriterResolved);
        Assert.AreEqual(
            DiagnosticErrorCategory.Finalization,
            errors.Chronology.Single().Category);
    }

    [TestMethod]
    public async Task CompleteAsync_FinalizationFailure_RetainsPartialActiveArtifact_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        ArtifactRecord partialArtifact = ArtifactRecord.CreateActive(
            "captures/deterministic__target-1__0001.pcap",
            "deterministic",
            ArtifactConfidentiality.Restricted,
            ArtifactRelation.Original);
        var provider = new DeterministicCaptureProvider
        {
            WaitForFinalizationAsyncHandler = (_, _) => Task.FromResult(
                CaptureProviderFinalizationResult.Failed(
                    CaptureProviderFailureCode.FinalizationFailed,
                    "The controlled artifact remained active.",
                    new[] { partialArtifact })),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Failed, completion.State);
        Assert.IsTrue(completion.WriterResolved);
        Assert.AreEqual(1, completion.Artifacts.Count);
        Assert.AreSame(partialArtifact, completion.Artifacts.Single());
        Assert.AreEqual(
            ArtifactFinalizationState.Active,
            completion.Artifacts.Single().FinalizationState);
    }

    [TestMethod]
    public void Finalized_ActiveArtifact_StillRejectsFalseSuccessfulFinalization_Issue64410325()
    {
        ArtifactRecord activeArtifact = ArtifactRecord.CreateActive(
            "captures/deterministic__target-1__0001.pcap",
            "deterministic",
            ArtifactConfidentiality.Restricted,
            ArtifactRelation.Original);

        Assert.ThrowsExactly<ArgumentException>(
            () => CaptureProviderFinalizationResult.Finalized(
                "Invalid success.",
                new[] { activeArtifact }));
    }

    [TestMethod]
    public async Task CompleteAsync_NullFinalizationResult_ClassifiesProviderContractFailure_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            WaitForFinalizationAsyncHandler = static (_, _) =>
                Task.FromResult<CaptureProviderFinalizationResult>(null!),
        };
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            CancellationToken.None);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Failed, completion.State);
        Assert.AreEqual(
            CaptureProviderFailureCode.FinalizationFailed,
            completion.FailureCode);
        Assert.AreEqual("FinalizationFailed", errors.Chronology.Single().Code);
    }

    [TestMethod]
    public async Task CompleteAsync_CancelledStop_LeavesWriterUnresolved_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider();
        var errors = new DiagnosticErrorLedger();
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        // Act
        CaptureProviderCompletionResult completion = await session.CompleteAsync(
            BoundedTimeouts,
            cancellation.Token);

        // Assert
        Assert.AreEqual(CaptureProviderLifecycleState.Abandoned, completion.State);
        Assert.AreEqual(CaptureProviderFailureCode.Cancelled, completion.FailureCode);
        Assert.IsFalse(completion.WriterResolved);
        Assert.IsFalse(provider.Calls.Contains("Stop"));
        Assert.IsFalse(provider.Calls.Contains("Finalization"));
    }

    [TestMethod]
    public async Task ProviderFailures_DoNotOverwritePrimaryProtocolError_Issue64410325()
    {
        // Arrange
        using ProviderTestContext context = ProviderTestContext.Create();
        var provider = new DeterministicCaptureProvider
        {
            RequestStopAsyncHandler = static (_, _) => Task.FromResult(
                CaptureProviderStopResult.Failed(
                    writerResolved: false,
                    CaptureProviderFailureCode.StopFailed,
                    "The controlled stop failed.")),
        };
        var errors = new DiagnosticErrorLedger();
        errors.RecordProtocolError(
            "ProtocolAssertionFailed",
            "The protocol assertion failed.",
            DateTimeOffset.Parse("2026-10-02T16:00:00Z"));
        CaptureProviderOrchestrator orchestrator = CaptureProviderOrchestrator.CreateEnabled(errors);
        CaptureProviderSession session = await orchestrator.StartAsync(
            () => context.Request,
            () => provider,
            BoundedTimeouts,
            CancellationToken.None);

        // Act
        await session.CompleteAsync(BoundedTimeouts, CancellationToken.None);

        // Assert
        Assert.AreEqual("ProtocolAssertionFailed", errors.PrimaryProtocolError?.Code);
        CollectionAssert.AreEqual(
            new[] { "ProtocolAssertionFailed", "StopFailed" },
            errors.Chronology.Select(error => error.Code).ToArray());
    }

    [TestMethod]
    public void Capabilities_ControlledDouble_ReportsUnverifiedCoverageAndExplicitSemantics_Issue64410325()
    {
        // Act
        CaptureProviderCapabilities capabilities =
            DeterministicCaptureProvider.CreateCapabilities();

        // Assert
        Assert.AreEqual(CoverageQualification.Unverified, capabilities.Qualification);
        CollectionAssert.AreEqual(new[] { "TestTarget" }, capabilities.SupportedTargetKinds.ToArray());
        CollectionAssert.AreEqual(new[] { "pcap" }, capabilities.NativeFormats.ToArray());
        Assert.IsFalse(string.IsNullOrWhiteSpace(capabilities.TrafficVisibility));
        Assert.IsFalse(string.IsNullOrWhiteSpace(capabilities.LimitSemantics));
        Assert.IsFalse(string.IsNullOrWhiteSpace(capabilities.StopSemantics));
        Assert.IsFalse(string.IsNullOrWhiteSpace(capabilities.ReadinessSemantics));
        CollectionAssert.Contains(capabilities.KnownExclusions.ToArray(), "No hardware visibility.");
    }
}
