// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Text.Json;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Errors;

/// <summary>
/// Red tests for Task 64410323 independent, chronological diagnostic errors.
/// </summary>
[TestClass]
public sealed class ErrorLedgerTests
{
    [TestMethod]
    public void Record_SecondaryDiagnosticFailures_DoesNotOverwritePrimaryProtocolError_Issue64410323()
    {
        // Arrange
        var ledger = new DiagnosticErrorLedger();
        ledger.RecordProtocolError(
            "ProtocolAssertionFailed",
            "The protocol assertion failed.",
            DateTimeOffset.Parse("2026-10-01T17:00:00Z"));

        // Act
        ledger.Record(DiagnosticErrorCategory.Capture, "ExitedEarly", "Capture exited.", DateTimeOffset.Parse("2026-10-01T17:00:01Z"));
        ledger.Record(DiagnosticErrorCategory.Storage, "StorageUnavailable", "Storage failed.", DateTimeOffset.Parse("2026-10-01T17:00:02Z"));
        ledger.Record(DiagnosticErrorCategory.Cleanup, "CleanupFailed", "Cleanup failed.", DateTimeOffset.Parse("2026-10-01T17:00:03Z"));
        ledger.Record(DiagnosticErrorCategory.Finalization, "FinalizationFailed", "Finalization failed.", DateTimeOffset.Parse("2026-10-01T17:00:04Z"));

        // Assert
        Assert.AreEqual("ProtocolAssertionFailed", ledger.PrimaryProtocolError?.Code);
    }

    [TestMethod]
    public void Serialize_ErrorsRecordedAcrossFailureChannels_RetainsOccurrenceChronology_Issue64410323()
    {
        // Arrange
        ManifestDocument manifest = CreateBaselineManifest();
        manifest.Errors.RecordProtocolError(
            "ProtocolAssertionFailed",
            "The protocol assertion failed.",
            DateTimeOffset.Parse("2026-10-01T17:00:00Z"));
        manifest.Errors.Record(
            DiagnosticErrorCategory.Capture,
            "ExitedEarly",
            "Capture exited.",
            DateTimeOffset.Parse("2026-10-01T17:00:01Z"));
        manifest.Errors.Record(
            DiagnosticErrorCategory.Storage,
            "StorageUnavailable",
            "Storage failed.",
            DateTimeOffset.Parse("2026-10-01T17:00:02Z"));
        manifest.Errors.Record(
            DiagnosticErrorCategory.Cleanup,
            "CleanupFailed",
            "Cleanup failed.",
            DateTimeOffset.Parse("2026-10-01T17:00:03Z"));
        manifest.Errors.Record(
            DiagnosticErrorCategory.Finalization,
            "FinalizationFailed",
            "Finalization failed.",
            DateTimeOffset.Parse("2026-10-01T17:00:04Z"));

        // Act
        string json = ManifestSerializer.Serialize(manifest);
        using JsonDocument document = JsonDocument.Parse(json);
        string[] actualCodes = document.RootElement
            .GetProperty("errors")
            .EnumerateArray()
            .Select(error => error.GetProperty("code").GetString()!)
            .ToArray();

        // Assert
        CollectionAssert.AreEqual(
            new[]
            {
                "ProtocolAssertionFailed",
                "ExitedEarly",
                "StorageUnavailable",
                "CleanupFailed",
                "FinalizationFailed",
            },
            actualCodes);
    }

    [TestMethod]
    public void DeserializeThenRecord_ErrorSequenceGap_PreservesIdsAndAdvancesCounter_Issue64410323()
    {
        ManifestDocument manifest = CreateBaselineManifest();
        Assert.ThrowsExactly<ArgumentException>(() => manifest.Errors.Record(
            DiagnosticErrorCategory.Capture,
            string.Empty,
            "Rejected error.",
            DateTimeOffset.Parse("2026-10-01T16:59:59Z")));
        manifest.Errors.RecordProtocolError(
            "ProtocolAssertionFailed",
            "The protocol assertion failed.",
            DateTimeOffset.Parse("2026-10-01T17:00:00Z"));
        manifest.Errors.Record(
            DiagnosticErrorCategory.Storage,
            "StorageUnavailable",
            "Storage failed.",
            DateTimeOffset.Parse("2026-10-01T17:00:01Z"));

        string json = ManifestSerializer.Serialize(manifest);
        ManifestDocument restored = ManifestSerializer.Deserialize(json);
        DiagnosticError next = restored.Errors.Record(
            DiagnosticErrorCategory.Cleanup,
            "CleanupFailed",
            "Cleanup failed.",
            DateTimeOffset.Parse("2026-10-01T17:00:02Z"));

        CollectionAssert.AreEqual(
            new long[] { 2, 3, 4 },
            restored.Errors.Chronology.Select(error => error.Sequence).ToArray());
        Assert.AreEqual(4, next.Sequence);
        Assert.AreEqual(
            "ProtocolAssertionFailed",
            restored.Errors.PrimaryProtocolError?.Code);
    }

    [TestMethod]
    public void Deserialize_DuplicateErrorSequences_RejectsMalformedChronology_Issue64410323()
    {
        string json = $$"""
            {
              "schemaVersion": "{{ManifestSchema.SupportedVersion}}",
              "errors": [
                {
                  "sequence": 2,
                  "category": "Capture",
                  "code": "ExitedEarly",
                  "message": "Capture exited.",
                  "occurredAt": "2026-10-01T17:00:00Z"
                },
                {
                  "sequence": 2,
                  "category": "Storage",
                  "code": "StorageUnavailable",
                  "message": "Storage failed.",
                  "occurredAt": "2026-10-01T17:00:01Z"
                }
              ],
              "artifacts": []
            }
            """;

        Assert.ThrowsExactly<ManifestSerializationException>(
            () => ManifestSerializer.Deserialize(json));
    }

    [TestMethod]
    public void Deserialize_OutOfOrderErrorSequences_RejectsMalformedChronology_Issue64410323()
    {
        string json = $$"""
            {
              "schemaVersion": "{{ManifestSchema.SupportedVersion}}",
              "errors": [
                {
                  "sequence": 3,
                  "category": "Capture",
                  "code": "ExitedEarly",
                  "message": "Capture exited.",
                  "occurredAt": "2026-10-01T17:00:00Z"
                },
                {
                  "sequence": 2,
                  "category": "Storage",
                  "code": "StorageUnavailable",
                  "message": "Storage failed.",
                  "occurredAt": "2026-10-01T17:00:01Z"
                }
              ],
              "artifacts": []
            }
            """;

        Assert.ThrowsExactly<ManifestSerializationException>(
            () => ManifestSerializer.Deserialize(json));
    }

    [TestMethod]
    public void DeserializeThenRecord_NextToMaximumPersistedSequence_AppendsAndRoundTrips_Issue64410323()
    {
        string json = CreateManifestJsonWithErrorSequence(long.MaxValue - 2);
        ManifestDocument restored = ManifestSerializer.Deserialize(json);

        DiagnosticError next = restored.Errors.Record(
            DiagnosticErrorCategory.Cleanup,
            "CleanupFailed",
            "Cleanup failed.",
            DateTimeOffset.Parse("2026-10-01T17:00:01Z"));
        ManifestDocument roundTripped = ManifestSerializer.Deserialize(
            ManifestSerializer.Serialize(restored));

        Assert.AreEqual(long.MaxValue - 1, next.Sequence);
        CollectionAssert.AreEqual(
            new[] { long.MaxValue - 2, long.MaxValue - 1 },
            roundTripped.Errors.Chronology
                .Select(error => error.Sequence)
                .ToArray());
    }

    [TestMethod]
    public void DeserializeThenRecord_MaximumPersistedSequence_RejectsExhaustedAppendWithoutMutation_Issue64410323()
    {
        string json = CreateManifestJsonWithErrorSequence(long.MaxValue - 1);
        ManifestDocument restored = ManifestSerializer.Deserialize(json);

        InvalidOperationException exception =
            Assert.ThrowsExactly<InvalidOperationException>(
                () => restored.Errors.Record(
                    DiagnosticErrorCategory.Cleanup,
                    "CleanupFailed",
                    "Cleanup failed.",
                    DateTimeOffset.Parse("2026-10-01T17:00:01Z")));
        ManifestDocument roundTripped = ManifestSerializer.Deserialize(
            ManifestSerializer.Serialize(restored));

        StringAssert.Contains(exception.Message, "exhausted");
        CollectionAssert.AreEqual(
            new[] { long.MaxValue - 1 },
            roundTripped.Errors.Chronology
                .Select(error => error.Sequence)
                .ToArray());
    }

    private static string CreateManifestJsonWithErrorSequence(long sequence)
    {
        ManifestDocument manifest = CreateBaselineManifest();
        manifest.Errors.Record(
            DiagnosticErrorCategory.Capture,
            "ExitedEarly",
            "Capture exited.",
            DateTimeOffset.Parse("2026-10-01T17:00:00Z"));
        string json = ManifestSerializer.Serialize(manifest);
        const string SequenceToken = "\"sequence\": 1";

        Assert.IsTrue(
            json.Contains(SequenceToken, StringComparison.Ordinal),
            "The test fixture must contain the first allocated sequence.");
        return json.Replace(
            SequenceToken,
            $"\"sequence\": {sequence}",
            StringComparison.Ordinal);
    }

    private static ManifestDocument CreateBaselineManifest()
    {
        return new ManifestDocument(ManifestSchema.SupportedVersion)
        {
            ProtocolResult = ProtocolResultState.Failed,
            Collection = new CollectionEvidence(
                CollectionStatus.Partial,
                plannedArtifactCount: 1,
                usableArtifactCount: 1,
                noTrafficExpected: false,
                EvidenceReasonCode.CollectionGap),
            CoverageQualification = CoverageQualification.Unverified,
            CleanupStatus = LifecycleStatus.Failed,
            FinalizationStatus = LifecycleStatus.Failed,
            RunnerResult = RunnerResultState.Failed,
            CompletionState = CompletionState.Interrupted,
        };
    }
}