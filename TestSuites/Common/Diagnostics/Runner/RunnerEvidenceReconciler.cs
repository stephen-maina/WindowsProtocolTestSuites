// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Storage;
using StorageArtifactPath =
    Microsoft.Protocols.TestSuites.Diagnostics.Storage.ArtifactPath;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Runner;

public enum RunnerReconciliationStatus
{
    AuthoritativeMatch,
    NoMatch,
    AmbiguousMatch,
    UnsupportedOutcome,
}

public static class RunnerEvidenceReconciler
{
    internal const string TrxEvidenceRelativePath = "runner/results.trx";

    private static readonly string[] ReconciliationMetadataKeys =
    {
        RunnerCorrelationMetadata.OutcomeAuthority,
        RunnerCorrelationMetadata.ReconciliationStatus,
        RunnerCorrelationMetadata.CandidateCount,
        RunnerCorrelationMetadata.TrxSha256,
        RunnerCorrelationMetadata.TrxRunId,
        RunnerCorrelationMetadata.TestId,
        RunnerCorrelationMetadata.ExecutionId,
    };

    public static void Reconcile(
        string runRoot,
        string trxPath,
        string stdoutPath,
        string stderrPath,
        string bootstrapPath,
        int runnerExitCode,
        RunnerProvenance provenance)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        string canonicalRunRoot = RequireAbsoluteDirectory(
            runRoot,
            nameof(runRoot));
        string runId = RunnerRunContext.ValidateRunId(
            new DirectoryInfo(canonicalRunRoot).Name);
        string canonicalTrxPath = RequireRunArtifact(
            canonicalRunRoot,
            trxPath,
            nameof(trxPath));
        string canonicalStdoutPath = RequireRunArtifact(
            canonicalRunRoot,
            stdoutPath,
            nameof(stdoutPath));
        string canonicalStderrPath = RequireRunArtifact(
            canonicalRunRoot,
            stderrPath,
            nameof(stderrPath));
        string canonicalBootstrapPath = RequireRunArtifact(
            canonicalRunRoot,
            bootstrapPath,
            nameof(bootstrapPath));

        TrxRun trxRun = TrxRunReader.Read(canonicalTrxPath);
        string trxSha256 = RunnerProvenance.ComputeFileSha256(
            canonicalTrxPath);
        IReadOnlyList<RunnerReconciliationRecord> records =
            ReconcileInvocationManifests(
                canonicalRunRoot,
                runId,
                trxRun,
                trxSha256);
        IReadOnlyList<RunnerArtifactEvidence> artifacts =
            CreateRunnerArtifactInventory(
                canonicalRunRoot,
                canonicalBootstrapPath,
                canonicalStderrPath,
                canonicalStdoutPath,
                canonicalTrxPath);
        string evidence = RunnerEvidenceSerializer.Serialize(
            runId,
            runnerExitCode,
            trxRun.RunId,
            trxRun.RejectedResultCount,
            artifacts,
            provenance,
            records);

        using ArtifactCheckpoint checkpoint =
            ArtifactStore.CreateCheckpointUnderRoot(
                canonicalRunRoot,
                "runner",
                "runner-evidence.json");
        checkpoint.WriteText(evidence);
        checkpoint.Commit();
    }

    private static IReadOnlyList<RunnerReconciliationRecord>
        ReconcileInvocationManifests(
            string runRoot,
            string runId,
            TrxRun trxRun,
            string trxSha256)
    {
        string testsRoot = StorageArtifactPath.CombineUnderRoot(
            runRoot,
            "tests");
        if (!Directory.Exists(testsRoot))
        {
            return Array.Empty<RunnerReconciliationRecord>();
        }

        StorageArtifactPath.EnsureNoReparsePoints(runRoot, testsRoot);
        var contexts = new List<ManifestReconciliationContext>();
        foreach (string invocationRoot in Directory
                     .EnumerateDirectories(
                         testsRoot,
                         "*",
                         SearchOption.TopDirectoryOnly)
                     .OrderBy(path => path, StorageArtifactPath.PathComparer))
        {
            StorageArtifactPath.EnsureNoReparsePoints(
                runRoot,
                invocationRoot);
            string manifestPath = Path.Combine(
                invocationRoot,
                "manifest.json");
            if (!File.Exists(manifestPath))
            {
                continue;
            }

            StorageArtifactPath.EnsureNoReparsePoints(
                runRoot,
                manifestPath);
            ManifestDocument manifest = ManifestSerializer.Deserialize(
                File.ReadAllText(manifestPath, Encoding.UTF8));
            string invocationId = ReadRequiredMetadata(
                manifest,
                RunnerCorrelationMetadata.InvocationId);
            string manifestRunId = ReadRequiredMetadata(
                manifest,
                RunnerCorrelationMetadata.RunId);
            string managedIdentity = ReadRequiredSha256Metadata(
                manifest,
                RunnerCorrelationMetadata.ManagedTestIdentitySha256);
            string displayIdentity = ReadRequiredSha256Metadata(
                manifest,
                RunnerCorrelationMetadata.TestDisplayNameSha256);

            contexts.Add(new ManifestReconciliationContext(
                invocationRoot,
                invocationId,
                manifest,
                manifestRunId,
                managedIdentity,
                displayIdentity));
        }

        Dictionary<
            (string RunId, string ManagedIdentity, string DisplayIdentity),
            int> manifestCardinalities = contexts
                .GroupBy(context => (
                    context.RunId,
                    context.ManagedIdentitySha256,
                    context.DisplayIdentitySha256))
                .ToDictionary(group => group.Key, group => group.Count());

        var records = new List<RunnerReconciliationRecord>();
        foreach (ManifestReconciliationContext context in contexts)
        {
            TrxTestResult[] candidates = string.Equals(
                    context.RunId,
                    runId,
                    StringComparison.Ordinal)
                ? trxRun.Results
                    .Where(result =>
                        string.Equals(
                            result.ManagedTestIdentitySha256,
                            context.ManagedIdentitySha256,
                            StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(
                            result.TestDisplayNameSha256,
                            context.DisplayIdentitySha256,
                            StringComparison.OrdinalIgnoreCase))
                    .ToArray()
                : Array.Empty<TrxTestResult>();
            int manifestCardinality = manifestCardinalities[(
                context.RunId,
                context.ManagedIdentitySha256,
                context.DisplayIdentitySha256)];
            RunnerReconciliationRecord record = ReconcileManifest(
                context.InvocationId,
                context.Manifest,
                candidates,
                manifestCardinality == 1,
                trxRun.RunId,
                trxSha256);

            using ArtifactCheckpoint checkpoint =
                new ArtifactInvocation(context.InvocationRoot)
                    .CreateCheckpoint("manifest.json");
            checkpoint.WriteText(
                ManifestSerializer.Serialize(context.Manifest));
            checkpoint.Commit();
            records.Add(record);
        }

        return records
            .OrderBy(record => record.InvocationId, StringComparer.Ordinal)
            .ToArray();
    }

    private sealed record ManifestReconciliationContext(
        string InvocationRoot,
        string InvocationId,
        ManifestDocument Manifest,
        string RunId,
        string ManagedIdentitySha256,
        string DisplayIdentitySha256);

    private static RunnerReconciliationRecord ReconcileManifest(
        string invocationId,
        ManifestDocument manifest,
        IReadOnlyList<TrxTestResult> candidates,
        bool hasUniqueManifestIdentity,
        string trxRunId,
        string trxSha256)
    {
        RunnerReconciliationStatus status;
        TrxTestResult? authoritativeResult = null;
        string authority;
        if (!hasUniqueManifestIdentity || candidates.Count > 1)
        {
            status = RunnerReconciliationStatus.AmbiguousMatch;
            authority = "runner-result-unavailable-ambiguous";
            manifest.ProtocolResult = ProtocolResultState.Unknown;
            manifest.RunnerResult = RunnerResultState.Unknown;
            manifest.CompletionState = CompletionState.Provisional;
        }
        else if (candidates.Count == 0)
        {
            status = RunnerReconciliationStatus.NoMatch;
            authority = "runner-result-unavailable-no-match";
            manifest.ProtocolResult = ProtocolResultState.Unknown;
            manifest.RunnerResult = RunnerResultState.Unknown;
            manifest.CompletionState = CompletionState.Provisional;
        }
        else
        {
            TrxTestResult candidate = candidates[0];
            if (!TryMapOutcome(
                    candidate.Outcome,
                    out ProtocolResultState protocolResult,
                    out RunnerResultState runnerResult))
            {
                status = RunnerReconciliationStatus.UnsupportedOutcome;
                authority =
                    "runner-result-unavailable-unsupported-outcome";
                manifest.ProtocolResult = ProtocolResultState.Unknown;
                manifest.RunnerResult = RunnerResultState.Unknown;
                manifest.CompletionState = CompletionState.Provisional;
            }
            else
            {
                status = RunnerReconciliationStatus.AuthoritativeMatch;
                authority = "vstest-trx";
                authoritativeResult = candidate;
                manifest.ProtocolResult = protocolResult;
                manifest.RunnerResult = runnerResult;
                manifest.CompletionState = CanComplete(
                        manifest,
                        protocolResult,
                        runnerResult)
                    ? manifest.FinalizationStatus ==
                        LifecycleStatus.Failed
                        ? CompletionState.Interrupted
                        : CompletionState.Final
                    : CompletionState.Provisional;
            }
        }

        ReplaceReconciliationMetadata(
            manifest,
            authority,
            status,
            candidates.Count,
            trxRunId,
            trxSha256,
            authoritativeResult);
        return new RunnerReconciliationRecord(
            invocationId,
            status,
            candidates.Count,
            authoritativeResult?.TestId,
            authoritativeResult?.ExecutionId,
            manifest.ProtocolResult,
            manifest.RunnerResult,
            manifest.CompletionState);
    }

    private static bool CanComplete(
        ManifestDocument manifest,
        ProtocolResultState protocolResult,
        RunnerResultState runnerResult)
    {
        if (protocolResult is ProtocolResultState.Pending or
                ProtocolResultState.Unknown ||
            runnerResult is RunnerResultState.Pending or
                RunnerResultState.Unknown ||
            manifest.CleanupStatus == LifecycleStatus.Pending ||
            manifest.FinalizationStatus == LifecycleStatus.Pending ||
            manifest.UnresolvedWriters.Count != 0 ||
            manifest.Artifacts.Any(artifact =>
                artifact.FinalizationState !=
                ArtifactFinalizationState.Finalized))
        {
            return false;
        }

        CollectionValidationResult validation =
            CollectionEvidenceValidator.ValidateForFinalization(
                manifest.Collection);
        return validation.CanFinalize &&
               CollectionEquals(
                   manifest.Collection,
                   validation.NormalizedEvidence);
    }

    private static bool CollectionEquals(
        CollectionEvidence first,
        CollectionEvidence second)
    {
        return first.Status == second.Status &&
               first.PlannedArtifactCount == second.PlannedArtifactCount &&
               first.UsableArtifactCount == second.UsableArtifactCount &&
               first.NoTrafficExpected == second.NoTrafficExpected &&
               first.ReasonCode == second.ReasonCode;
    }

    private static bool TryMapOutcome(
        string outcome,
        out ProtocolResultState protocolResult,
        out RunnerResultState runnerResult)
    {
        (protocolResult, runnerResult) = outcome switch
        {
            "Passed" => (
                ProtocolResultState.Passed,
                RunnerResultState.Passed),
            "Failed" => (
                ProtocolResultState.Failed,
                RunnerResultState.Failed),
            "Inconclusive" => (
                ProtocolResultState.Inconclusive,
                RunnerResultState.Inconclusive),
            "Aborted" => (
                ProtocolResultState.Aborted,
                RunnerResultState.Aborted),
            "Timeout" or "TimedOut" => (
                ProtocolResultState.TimedOut,
                RunnerResultState.TimedOut),
            _ => (
                ProtocolResultState.Unknown,
                RunnerResultState.Unknown),
        };
        return protocolResult != ProtocolResultState.Unknown &&
               runnerResult != RunnerResultState.Unknown;
    }

    private static void ReplaceReconciliationMetadata(
        ManifestDocument manifest,
        string authority,
        RunnerReconciliationStatus status,
        int candidateCount,
        string trxRunId,
        string trxSha256,
        TrxTestResult? result)
    {
        manifest.Metadata.RemoveAll(entry =>
            ReconciliationMetadataKeys.Contains(
                entry.Key,
                StringComparer.Ordinal));
        AddMetadata(
            manifest,
            RunnerCorrelationMetadata.OutcomeAuthority,
            authority);
        AddMetadata(
            manifest,
            RunnerCorrelationMetadata.ReconciliationStatus,
            status.ToString());
        AddMetadata(
            manifest,
            RunnerCorrelationMetadata.CandidateCount,
            candidateCount.ToString(CultureInfo.InvariantCulture));
        AddMetadata(
            manifest,
            RunnerCorrelationMetadata.TrxSha256,
            trxSha256);
        AddMetadata(
            manifest,
            RunnerCorrelationMetadata.TrxRunId,
            trxRunId);
        if (result is not null)
        {
            AddMetadata(
                manifest,
                RunnerCorrelationMetadata.TestId,
                result.TestId);
            AddMetadata(
                manifest,
                RunnerCorrelationMetadata.ExecutionId,
                result.ExecutionId);
        }
    }

    private static void AddMetadata(
        ManifestDocument manifest,
        string key,
        string value)
    {
        manifest.Metadata.Add(
            new ManifestMetadataEntry(
                key,
                value,
                MetadataSensitivity.NonSensitive));
    }

    private static string ReadRequiredMetadata(
        ManifestDocument manifest,
        string key)
    {
        ManifestMetadataEntry[] entries = manifest.Metadata
            .Where(entry => string.Equals(
                entry.Key,
                key,
                StringComparison.Ordinal))
            .ToArray();
        if (entries.Length != 1 ||
            entries[0].Sensitivity != MetadataSensitivity.NonSensitive ||
            string.IsNullOrWhiteSpace(entries[0].Value))
        {
            throw new RunnerEvidenceException(
                $"The provisional manifest requires one non-sensitive '{key}' value.");
        }

        return entries[0].Value!;
    }

    private static string ReadRequiredSha256Metadata(
        ManifestDocument manifest,
        string key)
    {
        string value = ReadRequiredMetadata(manifest, key);
        if (value.Length != 64 ||
            value.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new RunnerEvidenceException(
                $"The provisional manifest metadata '{key}' is not a SHA-256 digest.");
        }

        return value.ToUpperInvariant();
    }

    private static IReadOnlyList<RunnerArtifactEvidence>
        CreateRunnerArtifactInventory(
            string runRoot,
            params string[] paths)
    {
        return paths
            .Select(path => RunnerArtifactEvidence.Create(runRoot, path))
            .OrderBy(
                artifact => artifact.RelativePath,
                StringComparer.Ordinal)
            .ToArray();
    }

    private static string RequireAbsoluteDirectory(
        string path,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException(
                "An absolute run root is required.",
                parameterName);
        }

        string canonical = Path.GetFullPath(path);
        if (!Path.IsPathFullyQualified(canonical) ||
            !Directory.Exists(canonical))
        {
            throw new RunnerEvidenceException(
                "The runner evidence root does not exist.");
        }

        StorageArtifactPath.EnsureNoReparsePoints(
            canonical,
            canonical);
        return canonical;
    }

    private static string RequireRunArtifact(
        string runRoot,
        string path,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException(
                "A runner artifact path is required.",
                parameterName);
        }

        string canonical = Path.GetFullPath(path);
        StorageArtifactPath.EnsureContained(runRoot, canonical);
        StorageArtifactPath.EnsureNoReparsePoints(runRoot, canonical);
        if (!File.Exists(canonical))
        {
            throw new RunnerEvidenceException(
                "An expected runner source artifact is unavailable.");
        }

        return canonical;
    }
}

internal sealed class RunnerArtifactEvidence
{
    private RunnerArtifactEvidence(
        string relativePath,
        long byteCount,
        string sha256)
    {
        RelativePath = relativePath;
        ByteCount = byteCount;
        Sha256 = sha256;
    }

    public string RelativePath { get; }

    public long ByteCount { get; }

    public string Sha256 { get; }

    public static RunnerArtifactEvidence Create(
        string runRoot,
        string artifactPath)
    {
        var info = new FileInfo(artifactPath);
        string relativePath = Path
            .GetRelativePath(runRoot, artifactPath)
            .Replace('\\', '/');
        _ = StorageArtifactPath.NormalizeRelativePath(relativePath);
        return new RunnerArtifactEvidence(
            relativePath,
            info.Length,
            RunnerProvenance.ComputeFileSha256(artifactPath));
    }
}

internal sealed class RunnerReconciliationRecord
{
    public RunnerReconciliationRecord(
        string invocationId,
        RunnerReconciliationStatus status,
        int candidateCount,
        string? testId,
        string? executionId,
        ProtocolResultState protocolResult,
        RunnerResultState runnerResult,
        CompletionState completionState)
    {
        InvocationId = invocationId;
        Status = status;
        CandidateCount = candidateCount;
        TestId = testId;
        ExecutionId = executionId;
        ProtocolResult = protocolResult;
        RunnerResult = runnerResult;
        CompletionState = completionState;
    }

    public string InvocationId { get; }

    public RunnerReconciliationStatus Status { get; }

    public int CandidateCount { get; }

    public string? TestId { get; }

    public string? ExecutionId { get; }

    public ProtocolResultState ProtocolResult { get; }

    public RunnerResultState RunnerResult { get; }

    public CompletionState CompletionState { get; }
}

internal sealed class TrxRun
{
    public TrxRun(
        string runId,
        IReadOnlyList<TrxTestResult> results,
        int rejectedResultCount)
    {
        RunId = runId;
        Results = results;
        RejectedResultCount = rejectedResultCount;
    }

    public string RunId { get; }

    public IReadOnlyList<TrxTestResult> Results { get; }

    public int RejectedResultCount { get; }
}

internal sealed class TrxTestResult
{
    public TrxTestResult(
        string testId,
        string executionId,
        string outcome,
        string managedTestIdentitySha256,
        string testDisplayNameSha256)
    {
        TestId = testId;
        ExecutionId = executionId;
        Outcome = outcome;
        ManagedTestIdentitySha256 = managedTestIdentitySha256;
        TestDisplayNameSha256 = testDisplayNameSha256;
    }

    public string TestId { get; }

    public string ExecutionId { get; }

    public string Outcome { get; }

    public string ManagedTestIdentitySha256 { get; }

    public string TestDisplayNameSha256 { get; }
}

internal static class TrxRunReader
{
    private static readonly XNamespace TrxNamespace =
        "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";

    public static TrxRun Read(string path)
    {
        XDocument document;
        try
        {
            using XmlReader reader = XmlReader.Create(
                path,
                new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    IgnoreComments = true,
                    MaxCharactersInDocument = 256L * 1024 * 1024,
                    XmlResolver = null,
                });
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (XmlException exception)
        {
            throw new RunnerEvidenceException(
                "The authoritative TRX is malformed.",
                exception);
        }
        catch (IOException exception)
        {
            throw new RunnerEvidenceException(
                "The authoritative TRX could not be read.",
                exception);
        }

        XElement root = document.Root ??
            throw new RunnerEvidenceException(
                "The authoritative TRX has no document root.");
        string runId = ReadGuid(root, "id", "TRX run ID");
        Dictionary<string, TrxDefinition> definitions = root
            .Descendants(TrxNamespace + "UnitTest")
            .Select(ReadDefinition)
            .GroupBy(definition => definition.TestId, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Count() == 1
                    ? group.Single()
                    : throw new RunnerEvidenceException(
                        "The authoritative TRX contains duplicate test definitions."),
                StringComparer.Ordinal);
        var acceptedResults = new List<TrxTestResult>();
        int rejectedResultCount = 0;
        foreach (XElement resultElement in root.Descendants(
                     TrxNamespace + "UnitTestResult"))
        {
            try
            {
                acceptedResults.Add(ReadResult(resultElement, definitions));
            }
            catch (RunnerEvidenceException)
            {
                rejectedResultCount++;
            }
        }

        TrxTestResult[] results = acceptedResults
            .OrderBy(result => result.TestId, StringComparer.Ordinal)
            .ThenBy(result => result.ExecutionId, StringComparer.Ordinal)
            .ToArray();
        return new TrxRun(
            runId,
            Array.AsReadOnly(results),
            rejectedResultCount);
    }

    private static TrxDefinition ReadDefinition(XElement element)
    {
        string testId = ReadGuid(element, "id", "TRX test ID");
        XElement method = element.Element(TrxNamespace + "TestMethod") ??
            throw new RunnerEvidenceException(
                "A TRX test definition has no TestMethod.");
        string className = ReadRequiredAttribute(
            method,
            "className",
            "TRX class name");
        string methodName = ReadRequiredAttribute(
            method,
            "name",
            "TRX method name");
        return new TrxDefinition(testId, className, methodName);
    }

    private static TrxTestResult ReadResult(
        XElement element,
        IReadOnlyDictionary<string, TrxDefinition> definitions)
    {
        string testId = ReadGuid(element, "testId", "TRX result test ID");
        string executionId = ReadGuid(
            element,
            "executionId",
            "TRX execution ID");
        string displayName = ReadRequiredAttribute(
            element,
            "testName",
            "TRX test display name");
        string outcome = ReadRequiredAttribute(
            element,
            "outcome",
            "TRX test outcome");
        if (!definitions.TryGetValue(testId, out TrxDefinition? definition))
        {
            throw new RunnerEvidenceException(
                "A TRX result has no matching test definition.");
        }

        return new TrxTestResult(
            testId,
            executionId,
            outcome,
            RunnerCorrelationMetadata.ComputeManagedTestIdentity(
                definition.ClassName,
                definition.MethodName),
            RunnerCorrelationMetadata.ComputeSha256(displayName));
    }

    private static string ReadGuid(
        XElement element,
        string attributeName,
        string description)
    {
        string raw = ReadRequiredAttribute(
            element,
            attributeName,
            description);
        if (!Guid.TryParse(raw, out Guid value))
        {
            throw new RunnerEvidenceException(
                $"The {description} is not a GUID.");
        }

        return value.ToString("D");
    }

    private static string ReadRequiredAttribute(
        XElement element,
        string attributeName,
        string description)
    {
        string? value = (string?)element.Attribute(attributeName);
        if (string.IsNullOrWhiteSpace(value) ||
            value.Any(char.IsControl))
        {
            throw new RunnerEvidenceException(
                $"The {description} is missing or invalid.");
        }

        return value;
    }

    private sealed class TrxDefinition
    {
        public TrxDefinition(
            string testId,
            string className,
            string methodName)
        {
            TestId = testId;
            ClassName = className;
            MethodName = methodName;
        }

        public string TestId { get; }

        public string ClassName { get; }

        public string MethodName { get; }
    }
}

internal static class RunnerEvidenceSerializer
{
    public static string Serialize(
        string runId,
        int runnerExitCode,
        string trxRunId,
        int rejectedResultCount,
        IEnumerable<RunnerArtifactEvidence> artifacts,
        RunnerProvenance provenance,
        IEnumerable<RunnerReconciliationRecord> records)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(
            stream,
            new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", "1.0");
            writer.WriteString("runId", runId);
            writer.WriteNumber("runnerExitCode", runnerExitCode);
            writer.WriteString("trxRunId", trxRunId);
            writer.WriteNumber(
                "rejectedResultCount",
                rejectedResultCount);
            writer.WriteString("reconciliationRelation", "Derived");
            writer.WriteString(
                "reconciliationSource",
                RunnerEvidenceReconciler.TrxEvidenceRelativePath);

            writer.WriteStartArray("artifacts");
            foreach (RunnerArtifactEvidence artifact in artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString(
                    "relativePath",
                    artifact.RelativePath);
                writer.WriteString("relation", "Original");
                writer.WriteString("confidentiality", "Restricted");
                writer.WriteNumber("byteCount", artifact.ByteCount);
                writer.WriteString("sha256", artifact.Sha256);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartObject("provenance");
            writer.WriteStartArray("binarySha256");
            foreach (string binarySha256 in provenance.BinarySha256)
            {
                writer.WriteStringValue(binarySha256);
            }

            writer.WriteEndArray();
            writer.WriteString(
                "filterSha256",
                provenance.FilterSha256);
            writer.WriteString(
                "canonicalConfigurationSha256",
                provenance.CanonicalConfigurationSha256);
            writer.WriteString(
                "deploymentConfigurationSha256",
                provenance.DeploymentConfigurationSha256);
            writer.WriteEndObject();

            writer.WriteStartArray("reconciliations");
            foreach (RunnerReconciliationRecord record in records)
            {
                writer.WriteStartObject();
                writer.WriteString(
                    "invocationId",
                    record.InvocationId);
                writer.WriteString("status", record.Status.ToString());
                writer.WriteNumber(
                    "candidateCount",
                    record.CandidateCount);
                if (record.TestId is not null)
                {
                    writer.WriteString("testId", record.TestId);
                    writer.WriteString(
                        "executionId",
                        record.ExecutionId);
                }

                writer.WriteString(
                    "protocolResult",
                    record.ProtocolResult.ToString());
                writer.WriteString(
                    "runnerResult",
                    record.RunnerResult.ToString());
                writer.WriteString(
                    "completionState",
                    record.CompletionState.ToString());
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }
}
