// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.TestSupport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Runner;

[TestClass]
public sealed class RunnerEvidenceReconciliationTests
{
    private const string ReconcilerTypeName =
        "Microsoft.Protocols.TestSuites.Diagnostics.Runner.RunnerEvidenceReconciler";
    private const string ProvenanceTypeName =
        "Microsoft.Protocols.TestSuites.Diagnostics.Runner.RunnerProvenance";
    private const string ExecutionPlanTypeName =
        "Microsoft.Protocols.TestSuites.Diagnostics.Runner.RunnerExecutionPlan";
    private const string ArtifactLayoutTypeName =
        "Microsoft.Protocols.TestSuites.Diagnostics.Runner.RunnerArtifactLayout";
    private const string CorrelationMetadataTypeName =
        "Microsoft.Protocols.TestSuites.Diagnostics.Runner.RunnerCorrelationMetadata";
    private const string ManagedIdentityKey = "runner.managedTestIdentitySha256";
    private const string DisplayIdentityKey = "runner.testDisplayNameSha256";
    private const string AttemptIdentityKey = "runner.attemptIdentity";
    private const string RunIdKey = "runner.runId";
    private const string InvocationIdKey = "invocationId";
    private const string OutcomeAuthorityKey = "outcomeAuthority";

    [TestMethod]
    public void Reconcile_UniqueStableIdentity_AppliesAuthoritativeTrxOutcome()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.TransferTests";
        const string MethodName = "SendPayload";
        const string DisplayName = "SendPayload";
        string invocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            DisplayName,
            attemptIdentity: "1");
        TrxCase result = TrxCase.Create(
            ClassName,
            MethodName,
            DisplayName,
            "Passed");
        fixture.WriteTrx(result);

        InvokeReconcile(fixture, runnerExitCode: 0);

        ManifestDocument manifest = fixture.ReadManifest(invocationId);
        Assert.AreEqual(ProtocolResultState.Passed, manifest.ProtocolResult);
        Assert.AreEqual(RunnerResultState.Passed, manifest.RunnerResult);
        Assert.AreEqual(CompletionState.Final, manifest.CompletionState);
        Assert.AreEqual(LifecycleStatus.Complete, manifest.CleanupStatus);
        Assert.AreEqual(LifecycleStatus.Complete, manifest.FinalizationStatus);
        Assert.AreEqual(
            "vstest-trx",
            ReadMetadata(manifest, OutcomeAuthorityKey));

        JsonElement reconciliation =
            fixture.ReadSingleReconciliation(invocationId);
        Assert.AreEqual(
            "AuthoritativeMatch",
            reconciliation.GetProperty("status").GetString());
        Assert.AreEqual(
            result.TestId,
            reconciliation.GetProperty("testId").GetString());
        Assert.AreEqual(
            result.ExecutionId,
            reconciliation.GetProperty("executionId").GetString());
    }

    [TestMethod]
    public void Reconcile_NoStableIdentityMatch_RemainsUnknownAndProvisional()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        string invocationId = fixture.AddManifest(
            "Contoso.Tests.TransferTests",
            "SendPayload",
            "SendPayload",
            attemptIdentity: "1");
        fixture.WriteTrx(TrxCase.Create(
            "Contoso.Tests.OtherTests",
            "SendPayload",
            "SendPayload",
            "Passed"));

        InvokeReconcile(fixture, runnerExitCode: 0);

        ManifestDocument manifest = fixture.ReadManifest(invocationId);
        Assert.AreEqual(ProtocolResultState.Unknown, manifest.ProtocolResult);
        Assert.AreEqual(RunnerResultState.Unknown, manifest.RunnerResult);
        Assert.AreEqual(CompletionState.Provisional, manifest.CompletionState);
        Assert.AreEqual(
            "runner-result-unavailable-no-match",
            ReadMetadata(manifest, OutcomeAuthorityKey));

        JsonElement reconciliation =
            fixture.ReadSingleReconciliation(invocationId);
        Assert.AreEqual(
            "NoMatch",
            reconciliation.GetProperty("status").GetString());
        Assert.AreEqual(0, reconciliation.GetProperty("candidateCount").GetInt32());
        Assert.IsFalse(reconciliation.TryGetProperty("testId", out _));
    }

    [TestMethod]
    public void Reconcile_MultipleStableIdentityMatches_RemainsAmbiguousWithoutGuessing()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.TransferTests";
        const string MethodName = "SendPayload";
        const string DisplayName = "SendPayload";
        string invocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            DisplayName,
            attemptIdentity: "1");
        fixture.WriteTrx(
            TrxCase.Create(ClassName, MethodName, DisplayName, "Passed"),
            TrxCase.Create(ClassName, MethodName, DisplayName, "Failed"));

        InvokeReconcile(fixture, runnerExitCode: 1);

        ManifestDocument manifest = fixture.ReadManifest(invocationId);
        Assert.AreEqual(ProtocolResultState.Unknown, manifest.ProtocolResult);
        Assert.AreEqual(RunnerResultState.Unknown, manifest.RunnerResult);
        Assert.AreEqual(CompletionState.Provisional, manifest.CompletionState);
        Assert.AreEqual(
            "runner-result-unavailable-ambiguous",
            ReadMetadata(manifest, OutcomeAuthorityKey));

        JsonElement reconciliation =
            fixture.ReadSingleReconciliation(invocationId);
        Assert.AreEqual(
            "AmbiguousMatch",
            reconciliation.GetProperty("status").GetString());
        Assert.AreEqual(2, reconciliation.GetProperty("candidateCount").GetInt32());
        Assert.IsFalse(reconciliation.TryGetProperty("testId", out _));
    }

    [TestMethod]
    public void Reconcile_MultipleRetryManifestsAndOneRetainedResult_LeavesEveryAttemptAmbiguous()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.RetryTests";
        const string MethodName = "EventuallySucceeds";
        const string DisplayName = "EventuallySucceeds";
        string firstInvocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            DisplayName,
            attemptIdentity: "1");
        string secondInvocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            DisplayName,
            attemptIdentity: "2");
        fixture.WriteTrx(TrxCase.Create(
            ClassName,
            MethodName,
            DisplayName,
            "Passed"));

        InvokeReconcile(fixture, runnerExitCode: 0);

        foreach (string invocationId in new[]
                 {
                     firstInvocationId,
                     secondInvocationId,
                 })
        {
            ManifestDocument manifest = fixture.ReadManifest(invocationId);
            Assert.AreEqual(ProtocolResultState.Unknown, manifest.ProtocolResult);
            Assert.AreEqual(RunnerResultState.Unknown, manifest.RunnerResult);
            Assert.AreEqual(CompletionState.Provisional, manifest.CompletionState);
            Assert.AreEqual(
                "runner-result-unavailable-ambiguous",
                ReadMetadata(manifest, OutcomeAuthorityKey));

            JsonElement reconciliation =
                fixture.ReadSingleReconciliation(invocationId);
            Assert.AreEqual(
                "AmbiguousMatch",
                reconciliation.GetProperty("status").GetString());
            Assert.AreEqual(
                1,
                reconciliation.GetProperty("candidateCount").GetInt32());
            Assert.IsFalse(reconciliation.TryGetProperty("testId", out _));
        }
    }

    [TestMethod]
    public void Reconcile_CaseVariantManifestDigestsAndOneRetainedResult_LeavesEveryAttemptAmbiguous()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.RetryTests";
        const string MethodName = "EventuallySucceeds";
        const string DisplayName = "EventuallySucceeds";
        string firstInvocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            DisplayName,
            attemptIdentity: "1");
        string secondInvocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            DisplayName,
            attemptIdentity: "2",
            useLowercaseManagedIdentityMetadata: true);
        fixture.WriteTrx(TrxCase.Create(
            ClassName,
            MethodName,
            DisplayName,
            "Passed"));

        InvokeReconcile(fixture, runnerExitCode: 0);

        foreach (string invocationId in new[]
                 {
                     firstInvocationId,
                     secondInvocationId,
                 })
        {
            ManifestDocument manifest = fixture.ReadManifest(invocationId);
            Assert.AreEqual(ProtocolResultState.Unknown, manifest.ProtocolResult);
            Assert.AreEqual(RunnerResultState.Unknown, manifest.RunnerResult);
            Assert.AreEqual(CompletionState.Provisional, manifest.CompletionState);
            Assert.AreEqual(
                "runner-result-unavailable-ambiguous",
                ReadMetadata(manifest, OutcomeAuthorityKey));

            JsonElement reconciliation =
                fixture.ReadSingleReconciliation(invocationId);
            Assert.AreEqual(
                "AmbiguousMatch",
                reconciliation.GetProperty("status").GetString());
            Assert.AreEqual(
                1,
                reconciliation.GetProperty("candidateCount").GetInt32());
            Assert.IsFalse(reconciliation.TryGetProperty("testId", out _));
            Assert.IsFalse(
                reconciliation.TryGetProperty("executionId", out _));
        }
    }

    [TestMethod]
    public void Reconcile_DataRowsUseExactDisplayIdentityInsteadOfMethodCoincidence()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.DataTransferTests";
        const string MethodName = "SendPayload";
        TrxCase firstRow = TrxCase.Create(
            ClassName,
            MethodName,
            "SendPayload (\"row-a\")",
            "Passed");
        TrxCase secondRow = TrxCase.Create(
            ClassName,
            MethodName,
            "SendPayload (\"row-b\")",
            "Failed");
        string invocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            secondRow.DisplayName,
            attemptIdentity: "1");
        fixture.WriteTrx(firstRow, secondRow);

        InvokeReconcile(fixture, runnerExitCode: 1);

        ManifestDocument manifest = fixture.ReadManifest(invocationId);
        Assert.AreEqual(ProtocolResultState.Failed, manifest.ProtocolResult);
        Assert.AreEqual(RunnerResultState.Failed, manifest.RunnerResult);
        JsonElement reconciliation =
            fixture.ReadSingleReconciliation(invocationId);
        Assert.AreEqual(
            secondRow.TestId,
            reconciliation.GetProperty("testId").GetString());
        Assert.AreEqual(1, reconciliation.GetProperty("candidateCount").GetInt32());
    }

    [TestMethod]
    public void Reconcile_MstestDataRowMethodSignature_NormalizesBeforeHashing()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.DataTransferTests";
        const string DisplayName = "Rows (\"row-a\")";
        string invocationId = fixture.AddManifest(
            ClassName,
            "Rows(System.String)",
            DisplayName,
            attemptIdentity: "1");
        TrxCase result = TrxCase.Create(
            ClassName,
            "Rows",
            DisplayName,
            "Passed");
        fixture.WriteTrx(result);

        InvokeReconcile(fixture, runnerExitCode: 0);

        ManifestDocument manifest = fixture.ReadManifest(invocationId);
        Assert.AreEqual(ProtocolResultState.Passed, manifest.ProtocolResult);
        Assert.AreEqual(RunnerResultState.Passed, manifest.RunnerResult);
        Assert.AreEqual(
            "vstest-trx",
            ReadMetadata(manifest, OutcomeAuthorityKey));
        JsonElement reconciliation =
            fixture.ReadSingleReconciliation(invocationId);
        Assert.AreEqual(
            result.TestId,
            reconciliation.GetProperty("testId").GetString());
    }

    [TestMethod]
    public void Reconcile_RepeatedAttemptWithoutTrxAttemptIdentity_RemainsAmbiguous()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.RetryTests";
        const string MethodName = "EventuallySucceeds";
        const string DisplayName = "EventuallySucceeds";
        string invocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            DisplayName,
            attemptIdentity: "2");
        TrxCase definition = TrxCase.Create(
            ClassName,
            MethodName,
            DisplayName,
            "Failed");
        fixture.WriteTrx(
            definition,
            definition.WithNewExecution("Passed"));

        InvokeReconcile(fixture, runnerExitCode: 0);

        ManifestDocument manifest = fixture.ReadManifest(invocationId);
        Assert.AreEqual(ProtocolResultState.Unknown, manifest.ProtocolResult);
        Assert.AreEqual(RunnerResultState.Unknown, manifest.RunnerResult);
        Assert.AreEqual(CompletionState.Provisional, manifest.CompletionState);
        JsonElement reconciliation =
            fixture.ReadSingleReconciliation(invocationId);
        Assert.AreEqual(
            "AmbiguousMatch",
            reconciliation.GetProperty("status").GetString());
        Assert.AreEqual(2, reconciliation.GetProperty("candidateCount").GetInt32());
    }

    [TestMethod]
    public void Reconcile_NotExecutedOutcome_RemainsUnknownAndProvisional()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.OutcomeTests";
        const string MethodName = "Unresolved";
        string invocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            MethodName,
            attemptIdentity: "1");
        fixture.WriteTrx(TrxCase.Create(
            ClassName,
            MethodName,
            MethodName,
            "NotExecuted"));

        InvokeReconcile(fixture, runnerExitCode: 0);

        ManifestDocument manifest = fixture.ReadManifest(invocationId);
        Assert.AreEqual(ProtocolResultState.Unknown, manifest.ProtocolResult);
        Assert.AreEqual(RunnerResultState.Unknown, manifest.RunnerResult);
        Assert.AreEqual(CompletionState.Provisional, manifest.CompletionState);
        Assert.AreEqual(
            "runner-result-unavailable-unsupported-outcome",
            ReadMetadata(manifest, OutcomeAuthorityKey));
        JsonElement reconciliation =
            fixture.ReadSingleReconciliation(invocationId);
        Assert.AreEqual(
            "UnsupportedOutcome",
            reconciliation.GetProperty("status").GetString());
        Assert.AreEqual(
            1,
            reconciliation.GetProperty("candidateCount").GetInt32());
        Assert.IsFalse(reconciliation.TryGetProperty("testId", out _));
    }

    [TestMethod]
    public void Reconcile_MalformedResultRecord_DoesNotBlockUnrelatedValidResult()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.HostileInputTests";
        const string MethodName = "PlainPasses";
        string invocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            MethodName,
            attemptIdentity: "1");
        TrxCase validResult = TrxCase.Create(
            ClassName,
            MethodName,
            MethodName,
            "Passed");
        TrxCase malformedResult = TrxCase.Create(
            ClassName,
            "NewlineRow",
            "NewlineRow (\"line1\nline2\")",
            "Passed");
        fixture.WriteTrx(validResult, malformedResult);

        InvokeReconcile(fixture, runnerExitCode: 0);

        ManifestDocument manifest = fixture.ReadManifest(invocationId);
        Assert.AreEqual(ProtocolResultState.Passed, manifest.ProtocolResult);
        using JsonDocument evidence = fixture.ReadRunnerEvidence();
        Assert.AreEqual(
            1,
            evidence.RootElement.GetProperty("rejectedResultCount").GetInt32());
    }

    [TestMethod]
    public void Reconcile_AuthoritativeResult_PreservesIndependentCollectionAndCleanupDimensions()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.TransferTests";
        const string MethodName = "SendPayload";
        string invocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            "SendPayload",
            attemptIdentity: "1",
            collection: new CollectionEvidence(
                CollectionStatus.Partial,
                plannedArtifactCount: 2,
                usableArtifactCount: 1,
                noTrafficExpected: false,
                EvidenceReasonCode.CollectionGap),
            cleanupStatus: LifecycleStatus.Failed,
            finalizationStatus: LifecycleStatus.Failed);
        fixture.WriteTrx(TrxCase.Create(
            ClassName,
            MethodName,
            "SendPayload",
            "Passed"));

        InvokeReconcile(fixture, runnerExitCode: 1);

        ManifestDocument manifest = fixture.ReadManifest(invocationId);
        Assert.AreEqual(ProtocolResultState.Passed, manifest.ProtocolResult);
        Assert.AreEqual(RunnerResultState.Passed, manifest.RunnerResult);
        Assert.AreEqual(CollectionStatus.Partial, manifest.Collection.Status);
        Assert.AreEqual(LifecycleStatus.Failed, manifest.CleanupStatus);
        Assert.AreEqual(LifecycleStatus.Failed, manifest.FinalizationStatus);
        Assert.AreEqual(CompletionState.Interrupted, manifest.CompletionState);
        Assert.AreEqual(
            1,
            fixture.ReadRunnerEvidence()
                .RootElement
                .GetProperty("runnerExitCode")
                .GetInt32());
    }

    [TestMethod]
    public void Reconcile_ProvenanceProjection_DoesNotPersistRawSecretsOrPaths()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string Secret = "b04b-command-secret";
        string secretBinary = Path.Combine(
            fixture.RunRoot,
            $"binary-{Secret}.dll");
        string secretConfig = Path.Combine(
            fixture.RunRoot,
            $"config-{Secret}.ptfconfig");
        string secretDeployment = Path.Combine(
            fixture.RunRoot,
            $"deployment-{Secret}.ptfconfig");
        File.WriteAllText(secretBinary, Secret, Encoding.UTF8);
        File.WriteAllText(secretConfig, $"<secret>{Secret}</secret>", Encoding.UTF8);
        File.WriteAllText(
            secretDeployment,
            $"<deployment>{Secret}</deployment>",
            Encoding.UTF8);
        fixture.WriteTrx();

        object provenance = CreateProvenance(
            new[] { secretBinary },
            $"TestCategory=BVT&token={Secret}",
            secretConfig,
            secretDeployment);
        InvokeReconcile(fixture, runnerExitCode: 0, provenance);

        string runnerEvidence = File.ReadAllText(fixture.RunnerEvidencePath);
        Assert.IsFalse(
            runnerEvidence.Contains(Secret, StringComparison.Ordinal));
        Assert.IsFalse(
            runnerEvidence.Contains(fixture.RunRoot, StringComparison.OrdinalIgnoreCase));
        using JsonDocument evidence = JsonDocument.Parse(runnerEvidence);
        JsonElement projected = evidence.RootElement.GetProperty("provenance");
        Assert.AreEqual(
            64,
            projected.GetProperty("filterSha256").GetString()!.Length);
        Assert.AreEqual(
            1,
            projected.GetProperty("binarySha256").GetArrayLength());
    }

    [TestMethod]
    public void Reconcile_RunnerOutputInventory_SeparatesOriginalAndDerivedEvidence()
    {
        using RunnerFixture fixture = RunnerFixture.Create(
            stdout: "runner stdout",
            stderr: "runner stderr",
            bootstrap: "bootstrap output");
        fixture.WriteTrx();

        InvokeReconcile(fixture, runnerExitCode: 0);

        using JsonDocument evidence = fixture.ReadRunnerEvidence();
        JsonElement[] artifacts = evidence.RootElement
            .GetProperty("artifacts")
            .EnumerateArray()
            .ToArray();
        string[] expectedOriginals =
        {
            "runner/bootstrap.log",
            "runner/stderr.log",
            "runner/stdout.log",
            "runner/results.trx",
        };
        CollectionAssert.AreEquivalent(
            expectedOriginals,
            artifacts
                .Where(element =>
                    element.GetProperty("relation").GetString() == "Original")
                .Select(element =>
                    element.GetProperty("relativePath").GetString())
                .ToArray());
        Assert.IsTrue(artifacts.All(element =>
            element.GetProperty("confidentiality").GetString() == "Restricted"));
        Assert.IsTrue(artifacts.All(element =>
            element.GetProperty("sha256").GetString()!.Length == 64));
        Assert.AreEqual(
            "Derived",
            evidence.RootElement
                .GetProperty("reconciliationRelation")
                .GetString());
        Assert.AreEqual(
            "runner/results.trx",
            evidence.RootElement
                .GetProperty("reconciliationSource")
                .GetString());
    }

    [TestMethod]
    public void Reconcile_RepeatedWithSameInputs_IsByteForByteIdempotent()
    {
        using RunnerFixture fixture = RunnerFixture.Create();
        const string ClassName = "Contoso.Tests.TransferTests";
        const string MethodName = "SendPayload";
        string invocationId = fixture.AddManifest(
            ClassName,
            MethodName,
            "SendPayload",
            attemptIdentity: "1");
        fixture.WriteTrx(TrxCase.Create(
            ClassName,
            MethodName,
            "SendPayload",
            "Passed"));
        object provenance = fixture.CreateDefaultProvenance();

        InvokeReconcile(fixture, runnerExitCode: 0, provenance);
        byte[] firstManifest = File.ReadAllBytes(fixture.ManifestPath(invocationId));
        byte[] firstEvidence = File.ReadAllBytes(fixture.RunnerEvidencePath);

        InvokeReconcile(fixture, runnerExitCode: 0, provenance);
        byte[] secondManifest = File.ReadAllBytes(fixture.ManifestPath(invocationId));
        byte[] secondEvidence = File.ReadAllBytes(fixture.RunnerEvidencePath);

        CollectionAssert.AreEqual(firstManifest, secondManifest);
        CollectionAssert.AreEqual(firstEvidence, secondEvidence);
    }

    [TestMethod]
    public void CreateExecutionPlan_DiagnosticsDisabled_DoesNotCreateArtifactDirectory()
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string canonicalConfig = Path.Combine(directory.Path, "suite.ptfconfig");
        string deploymentConfig = Path.Combine(directory.Path, "deployment.ptfconfig");
        string artifactRoot = Path.Combine(directory.Path, "must-not-exist");
        File.WriteAllText(
            canonicalConfig,
            CreatePtfConfig(
                ("Diagnostics.Enabled", "false"),
                ("Diagnostics.ArtifactRoot", artifactRoot + "*")),
            Encoding.UTF8);
        File.WriteAllText(
            deploymentConfig,
            CreatePtfConfig(("SutPassword", "not-read-by-b04b")),
            Encoding.UTF8);

        object plan = CreateExecutionPlan(
            canonicalConfig,
            deploymentConfig,
            "run-" + Guid.NewGuid().ToString("N"));

        Assert.IsFalse(ReadProperty<bool>(plan, "IsEnabled"));
        Assert.IsNull(ReadProperty<string?>(plan, "ArtifactRoot"));
        Assert.IsNull(ReadProperty<string?>(plan, "RunRoot"));
        Assert.IsFalse(Directory.Exists(artifactRoot));
    }

    [TestMethod]
    public void CreateArtifactLayout_ArtifactRootInsideSource_RejectsBeforeCreation()
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        string canonicalConfig = Path.Combine(buildRoot, "suite.ptfconfig");
        string deploymentConfig = Path.Combine(buildRoot, "deployment.ptfconfig");
        string artifactRoot = Path.Combine(sourceRoot, "diagnostics-artifacts");
        File.WriteAllText(
            canonicalConfig,
            CreatePtfConfig(
                ("Diagnostics.Enabled", "true"),
                ("Diagnostics.ArtifactRoot", artifactRoot)),
            Encoding.UTF8);
        File.WriteAllText(
            deploymentConfig,
            CreatePtfConfig(("SutComputerName", "sut")),
            Encoding.UTF8);
        object plan = CreateExecutionPlan(
            canonicalConfig,
            deploymentConfig,
            "run-" + Guid.NewGuid().ToString("N"));

        ArtifactStorageException exception =
            Assert.ThrowsExactly<ArtifactStorageException>(
                () => CreateArtifactLayout(plan, sourceRoot));

        Assert.AreEqual(
            ArtifactStorageFailure.ArtifactRootConflictsWithSource,
            exception.Failure);
        Assert.IsFalse(Directory.Exists(artifactRoot));
    }

    [TestMethod]
    public void CreateArtifactLayout_ArtifactRootInsideBuildOutput_RejectsBeforeCreation()
    {
        using TemporaryDirectory directory = TemporaryDirectory.Create();
        string sourceRoot = directory.CreateSubdirectory("source");
        string buildRoot = Path.Combine(
            sourceRoot,
            "bin",
            "Debug",
            "net8.0");
        Directory.CreateDirectory(buildRoot);
        string canonicalConfig = Path.Combine(buildRoot, "suite.ptfconfig");
        string deploymentConfig = Path.Combine(buildRoot, "deployment.ptfconfig");
        string artifactRoot = Path.Combine(buildRoot, "diagnostics-artifacts");
        File.WriteAllText(
            canonicalConfig,
            CreatePtfConfig(
                ("Diagnostics.Enabled", "true"),
                ("Diagnostics.ArtifactRoot", artifactRoot)),
            Encoding.UTF8);
        File.WriteAllText(
            deploymentConfig,
            CreatePtfConfig(("SutComputerName", "sut")),
            Encoding.UTF8);
        object plan = CreateExecutionPlan(
            canonicalConfig,
            deploymentConfig,
            "run-" + Guid.NewGuid().ToString("N"));

        ArtifactStorageException exception =
            Assert.ThrowsExactly<ArtifactStorageException>(
                () => CreateArtifactLayout(plan, sourceRoot));

        Assert.AreEqual(
            ArtifactStorageFailure.ArtifactRootConflictsWithBuild,
            exception.Failure);
        Assert.IsFalse(Directory.Exists(artifactRoot));
    }

    private static void InvokeReconcile(
        RunnerFixture fixture,
        int runnerExitCode,
        object? provenance = null)
    {
        Type reconcilerType = RequireProductionType(ReconcilerTypeName);
        MethodInfo method = RequireStaticMethod(reconcilerType, "Reconcile");
        object actualProvenance =
            provenance ?? fixture.CreateDefaultProvenance();
        InvokeUnwrapped(
            method,
            null,
            fixture.RunRoot,
            fixture.TrxPath,
            fixture.StdoutPath,
            fixture.StderrPath,
            fixture.BootstrapPath,
            runnerExitCode,
            actualProvenance);
    }

    private static object CreateProvenance(
        string[] binaryPaths,
        string? filter,
        string canonicalConfigurationPath,
        string deploymentConfigurationPath)
    {
        Type provenanceType = RequireProductionType(ProvenanceTypeName);
        MethodInfo method = RequireStaticMethod(provenanceType, "Create");
        return InvokeUnwrapped(
            method,
            null,
            binaryPaths,
            filter,
            canonicalConfigurationPath,
            deploymentConfigurationPath)!;
    }

    private static object CreateExecutionPlan(
        string canonicalConfigurationPath,
        string deploymentConfigurationPath,
        string runId)
    {
        Type planType = RequireProductionType(ExecutionPlanTypeName);
        MethodInfo method = RequireStaticMethod(planType, "Create");
        return InvokeUnwrapped(
            method,
            null,
            canonicalConfigurationPath,
            deploymentConfigurationPath,
            runId)!;
    }

    private static object CreateArtifactLayout(
        object executionPlan,
        string sourceRoot)
    {
        Type layoutType = RequireProductionType(ArtifactLayoutTypeName);
        MethodInfo method = RequireStaticMethod(layoutType, "Create");
        return InvokeUnwrapped(
            method,
            null,
            executionPlan,
            sourceRoot)!;
    }

    private static string ComputeManagedTestIdentity(
        string className,
        string methodName)
    {
        Type metadataType = RequireProductionType(CorrelationMetadataTypeName);
        MethodInfo? method = metadataType.GetMethod(
            "ComputeManagedTestIdentity",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.IsNotNull(
            method,
            $"The B04B production method '{metadataType.FullName}.ComputeManagedTestIdentity' is required.");
        return (string)InvokeUnwrapped(
            method!,
            null,
            className,
            methodName)!;
    }

    private static Type RequireProductionType(string fullName)
    {
        Type? type = typeof(ManifestDocument).Assembly.GetType(
            fullName,
            throwOnError: false,
            ignoreCase: false);
        Assert.IsNotNull(
            type,
            $"The B04B production type '{fullName}' is required.");
        return type!;
    }

    private static MethodInfo RequireStaticMethod(Type type, string methodName)
    {
        MethodInfo? method = type
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .SingleOrDefault(candidate =>
                string.Equals(
                    candidate.Name,
                    methodName,
                    StringComparison.Ordinal));
        Assert.IsNotNull(
            method,
            $"The B04B production method '{type.FullName}.{methodName}' is required.");
        return method!;
    }

    private static object? InvokeUnwrapped(
        MethodInfo method,
        object? target,
        params object?[] arguments)
    {
        try
        {
            return method.Invoke(target, arguments);
        }
        catch (TargetInvocationException exception)
            when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }

    private static T ReadProperty<T>(object instance, string propertyName)
    {
        PropertyInfo? property = instance
            .GetType()
            .GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);
        Assert.IsNotNull(
            property,
            $"Property '{propertyName}' is required on '{instance.GetType().FullName}'.");
        return (T)property!.GetValue(instance)!;
    }

    private static string? ReadMetadata(
        ManifestDocument manifest,
        string key)
    {
        return manifest.Metadata
            .Single(entry => string.Equals(
                entry.Key,
                key,
                StringComparison.Ordinal))
            .Value;
    }

    private static string ComputeSha256(string value)
    {
        return Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }

    private static string CreatePtfConfig(
        params (string Name, string Value)[] properties)
    {
        XNamespace configNamespace =
            "http://schemas.microsoft.com/windows/ProtocolsTest/2007/07/TestConfig";
        var document = new XDocument(
            new XElement(
                configNamespace + "TestSite",
                new XElement(
                    configNamespace + "Properties",
                    properties.Select(property =>
                        new XElement(
                            configNamespace + "Property",
                            new XAttribute("name", property.Name),
                            new XAttribute("value", property.Value))))));
        return document.ToString(SaveOptions.DisableFormatting);
    }

    private sealed class RunnerFixture : IDisposable
    {
        private static readonly XNamespace TrxNamespace =
            "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        private readonly TemporaryDirectory directory;
        private readonly Dictionary<string, string> manifestPaths = new(
            StringComparer.Ordinal);

        private RunnerFixture(
            TemporaryDirectory directory,
            string runId,
            string stdout,
            string stderr,
            string bootstrap)
        {
            this.directory = directory;
            RunId = runId;
            ArtifactRoot = directory.CreateSubdirectory("artifacts");
            RunRoot = Path.Combine(ArtifactRoot, RunId);
            string runnerRoot = Path.Combine(RunRoot, "runner");
            Directory.CreateDirectory(runnerRoot);
            Directory.CreateDirectory(Path.Combine(RunRoot, "tests"));
            TrxPath = Path.Combine(runnerRoot, "results.trx");
            StdoutPath = Path.Combine(runnerRoot, "stdout.log");
            StderrPath = Path.Combine(runnerRoot, "stderr.log");
            BootstrapPath = Path.Combine(runnerRoot, "bootstrap.log");
            RunnerEvidencePath = Path.Combine(
                runnerRoot,
                "runner-evidence.json");
            File.WriteAllText(StdoutPath, stdout, Encoding.UTF8);
            File.WriteAllText(StderrPath, stderr, Encoding.UTF8);
            File.WriteAllText(BootstrapPath, bootstrap, Encoding.UTF8);
            CanonicalConfigurationPath = Path.Combine(
                directory.Path,
                "suite.ptfconfig");
            DeploymentConfigurationPath = Path.Combine(
                directory.Path,
                "deployment.ptfconfig");
            BinaryPath = Path.Combine(directory.Path, "suite.dll");
            File.WriteAllText(
                CanonicalConfigurationPath,
                CreatePtfConfig(
                    ("Diagnostics.Enabled", "true"),
                    ("Diagnostics.ArtifactRoot", ArtifactRoot)),
                Encoding.UTF8);
            File.WriteAllText(
                DeploymentConfigurationPath,
                CreatePtfConfig(("SutComputerName", "sut")),
                Encoding.UTF8);
            File.WriteAllText(BinaryPath, "binary", Encoding.UTF8);
        }

        public string RunId { get; }

        public string ArtifactRoot { get; }

        public string RunRoot { get; }

        public string TrxPath { get; }

        public string StdoutPath { get; }

        public string StderrPath { get; }

        public string BootstrapPath { get; }

        public string RunnerEvidencePath { get; }

        public string CanonicalConfigurationPath { get; }

        public string DeploymentConfigurationPath { get; }

        public string BinaryPath { get; }

        public static RunnerFixture Create(
            string stdout = "",
            string stderr = "",
            string bootstrap = "")
        {
            return new RunnerFixture(
                TemporaryDirectory.Create(),
                "run-" + Guid.NewGuid().ToString("N"),
                stdout,
                stderr,
                bootstrap);
        }

        public string AddManifest(
            string className,
            string methodName,
            string displayName,
            string attemptIdentity,
            CollectionEvidence? collection = null,
            LifecycleStatus cleanupStatus = LifecycleStatus.Complete,
            LifecycleStatus finalizationStatus = LifecycleStatus.Complete,
            bool useLowercaseManagedIdentityMetadata = false)
        {
            string invocationId = Guid.NewGuid().ToString("N");
            string invocationRoot = Path.Combine(
                RunRoot,
                "tests",
                $"test__{invocationId}");
            Directory.CreateDirectory(invocationRoot);
            string manifestPath = Path.Combine(invocationRoot, "manifest.json");
            var manifest = new ManifestDocument(ManifestSchema.SupportedVersion)
            {
                ProtocolResult = ProtocolResultState.Pending,
                Collection = collection ?? new CollectionEvidence(
                    CollectionStatus.Unavailable,
                    plannedArtifactCount: 1,
                    usableArtifactCount: 0,
                    noTrafficExpected: false,
                    EvidenceReasonCode.ProviderUnsupported),
                CoverageQualification = CoverageQualification.Unsupported,
                CleanupStatus = cleanupStatus,
                FinalizationStatus = finalizationStatus,
                RunnerResult = RunnerResultState.Pending,
                CompletionState = CompletionState.Provisional,
            };
            manifest.Metadata.Add(
                new ManifestMetadataEntry(
                    InvocationIdKey,
                    invocationId,
                    MetadataSensitivity.NonSensitive));
            manifest.Metadata.Add(
                new ManifestMetadataEntry(
                    RunIdKey,
                    RunId,
                    MetadataSensitivity.NonSensitive));
            manifest.Metadata.Add(
                new ManifestMetadataEntry(
                    ManagedIdentityKey,
                    useLowercaseManagedIdentityMetadata
                        ? ComputeManagedTestIdentity(
                            className,
                            methodName).ToLowerInvariant()
                        : ComputeManagedTestIdentity(className, methodName),
                    MetadataSensitivity.NonSensitive));
            manifest.Metadata.Add(
                new ManifestMetadataEntry(
                    DisplayIdentityKey,
                    ComputeSha256(displayName),
                    MetadataSensitivity.NonSensitive));
            manifest.Metadata.Add(
                new ManifestMetadataEntry(
                    AttemptIdentityKey,
                    attemptIdentity,
                    MetadataSensitivity.NonSensitive));
            manifest.Metadata.Add(
                new ManifestMetadataEntry(
                    OutcomeAuthorityKey,
                    "provisional-not-authoritative",
                    MetadataSensitivity.NonSensitive));
            File.WriteAllText(
                manifestPath,
                ManifestSerializer.Serialize(manifest),
                Encoding.UTF8);
            manifestPaths.Add(invocationId, manifestPath);
            return invocationId;
        }

        public void WriteTrx(params TrxCase[] results)
        {
            Guid trxRunId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
            var definitions = results
                .GroupBy(result => result.TestId, StringComparer.Ordinal)
                .Select(group => group.First())
                .ToArray();
            var document = new XDocument(
                new XElement(
                    TrxNamespace + "TestRun",
                    new XAttribute("id", trxRunId),
                    new XElement(
                        TrxNamespace + "Times",
                        new XAttribute(
                            "creation",
                            "2026-10-06T12:00:00.0000000Z"),
                        new XAttribute(
                            "start",
                            "2026-10-06T12:00:00.0000000Z"),
                        new XAttribute(
                            "finish",
                            "2026-10-06T12:00:01.0000000Z")),
                    new XElement(
                        TrxNamespace + "Results",
                        results.Select(result =>
                            new XElement(
                                TrxNamespace + "UnitTestResult",
                                new XAttribute(
                                    "executionId",
                                    result.ExecutionId),
                                new XAttribute("testId", result.TestId),
                                new XAttribute("testName", result.DisplayName),
                                new XAttribute("outcome", result.Outcome)))),
                    new XElement(
                        TrxNamespace + "TestDefinitions",
                        definitions.Select(result =>
                            new XElement(
                                TrxNamespace + "UnitTest",
                                new XAttribute("name", result.DisplayName),
                                new XAttribute("id", result.TestId),
                                new XElement(
                                    TrxNamespace + "Execution",
                                    new XAttribute(
                                        "id",
                                        result.ExecutionId)),
                                new XElement(
                                    TrxNamespace + "TestMethod",
                                    new XAttribute(
                                        "codeBase",
                                        @"C:\runner\MS-SMBD_ServerTestSuite.dll"),
                                    new XAttribute(
                                        "className",
                                        result.ClassName),
                                    new XAttribute(
                                        "name",
                                        result.MethodName))))),
                    new XElement(
                        TrxNamespace + "ResultSummary",
                        new XAttribute("outcome", "Completed"),
                        new XElement(
                            TrxNamespace + "Counters",
                            new XAttribute("total", results.Length),
                            new XAttribute("executed", results.Length)))));
            File.WriteAllText(
                TrxPath,
                document.ToString(SaveOptions.DisableFormatting),
                Encoding.UTF8);
        }

        public object CreateDefaultProvenance()
        {
            return CreateProvenance(
                new[] { BinaryPath },
                "TestCategory=BVT",
                CanonicalConfigurationPath,
                DeploymentConfigurationPath);
        }

        public ManifestDocument ReadManifest(string invocationId)
        {
            return ManifestSerializer.Deserialize(
                File.ReadAllText(ManifestPath(invocationId)));
        }

        public string ManifestPath(string invocationId)
        {
            return manifestPaths[invocationId];
        }

        public JsonDocument ReadRunnerEvidence()
        {
            return JsonDocument.Parse(File.ReadAllText(RunnerEvidencePath));
        }

        public JsonElement ReadSingleReconciliation(string invocationId)
        {
            using JsonDocument evidence = ReadRunnerEvidence();
            return evidence.RootElement
                .GetProperty("reconciliations")
                .EnumerateArray()
                .Single(element =>
                    string.Equals(
                        element.GetProperty("invocationId").GetString(),
                        invocationId,
                        StringComparison.Ordinal))
                .Clone();
        }

        public void Dispose()
        {
            directory.Dispose();
        }
    }

    private sealed class TrxCase
    {
        private TrxCase(
            string className,
            string methodName,
            string displayName,
            string outcome,
            string testId,
            string executionId)
        {
            ClassName = className;
            MethodName = methodName;
            DisplayName = displayName;
            Outcome = outcome;
            TestId = testId;
            ExecutionId = executionId;
        }

        public string ClassName { get; }

        public string MethodName { get; }

        public string DisplayName { get; }

        public string Outcome { get; }

        public string TestId { get; }

        public string ExecutionId { get; }

        public static TrxCase Create(
            string className,
            string methodName,
            string displayName,
            string outcome)
        {
            return new TrxCase(
                className,
                methodName,
                displayName,
                outcome,
                Guid.NewGuid().ToString(),
                Guid.NewGuid().ToString());
        }

        public TrxCase WithNewExecution(string outcome)
        {
            return new TrxCase(
                ClassName,
                MethodName,
                DisplayName,
                outcome,
                TestId,
                Guid.NewGuid().ToString());
        }
    }
}
