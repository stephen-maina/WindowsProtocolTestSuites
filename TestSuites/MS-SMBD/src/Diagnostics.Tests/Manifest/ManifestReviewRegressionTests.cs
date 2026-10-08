// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text.Json;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Manifest;

[TestClass]
public sealed class ManifestReviewRegressionTests
{
    [TestMethod]
    public void Deserialize_MetadataWithoutSensitivity_RejectsUnclassifiedValue_Issue64410323()
    {
        const string secret = "unclassified-review-secret";
        string json = $$"""
            {
              "schemaVersion": "{{ManifestSchema.SupportedVersion}}",
              "metadata": [
                {
                  "key": "runner.arguments",
                  "value": "{{secret}}"
                }
              ],
              "artifacts": []
            }
            """;

        Assert.ThrowsExactly<ManifestSerializationException>(
            () => ManifestSerializer.Deserialize(json));
    }

    [TestMethod]
    public void DeserializeThenSerialize_NonSensitiveMetadata_PreservesInboundValue_Issue64410323()
    {
        const string value = "safe-runner-name";
        string json = $$"""
            {
              "schemaVersion": "{{ManifestSchema.SupportedVersion}}",
              "metadata": [
                {
                  "key": "runner.name",
                  "sensitivity": "NonSensitive",
                  "value": "{{value}}"
                }
              ],
              "artifacts": []
            }
            """;

        ManifestDocument manifest = ManifestSerializer.Deserialize(json);
        string serialized = ManifestSerializer.Serialize(manifest);

        Assert.IsTrue(serialized.Contains(value, StringComparison.Ordinal));
    }

    [TestMethod]
    public void DeserializeThenSerialize_SensitiveMetadata_DoesNotReemitInboundValue_Issue64410323()
    {
        const string secret = "review-secret-value";
        string json = $$"""
            {
              "schemaVersion": "{{ManifestSchema.SupportedVersion}}",
              "metadata": [
                {
                  "key": "runner.arguments",
                  "sensitivity": "Sensitive",
                  "value": "{{secret}}"
                }
              ],
              "artifacts": []
            }
            """;

        ManifestDocument manifest = ManifestSerializer.Deserialize(json);
        string serialized = ManifestSerializer.Serialize(manifest);

        Assert.IsFalse(serialized.Contains(secret, StringComparison.Ordinal));
        Assert.IsTrue(serialized.Contains("[REDACTED]", StringComparison.Ordinal));
    }

    [TestMethod]
    public void DeserializeThenSerialize_SecretMetadata_OmitsInboundValue_Issue64410323()
    {
        const string secret = "classified-review-secret";
        string json = $$"""
            {
              "schemaVersion": "{{ManifestSchema.SupportedVersion}}",
              "metadata": [
                {
                  "key": "runner.token",
                  "sensitivity": "Secret",
                  "value": "{{secret}}"
                }
              ],
              "artifacts": []
            }
            """;

        ManifestDocument manifest = ManifestSerializer.Deserialize(json);
        string serialized = ManifestSerializer.Serialize(manifest);

        Assert.IsFalse(serialized.Contains(secret, StringComparison.Ordinal));
        Assert.IsFalse(serialized.Contains("\"value\"", StringComparison.Ordinal));
    }

    [TestMethod]
    public void CreateSensitiveMetadata_SecretRedactionMarker_RejectsMarker_Issue64410323()
    {
        const string secret = "caller-controlled-secret-marker";

        Assert.ThrowsExactly<ArgumentException>(() => new ManifestMetadataEntry(
            "runner.arguments",
            secret,
            MetadataSensitivity.Sensitive,
            secret));
    }

    [DataTestMethod]
    [DataRow("Unknown")]
    [DataRow("TimedOut")]
    public void Deserialize_RequiredProtocolResultState_RoundTripsState_Issue64410323(
        string expectedState)
    {
        string json = $$"""
            {
              "schemaVersion": "{{ManifestSchema.SupportedVersion}}",
              "protocolResult": "{{expectedState}}",
              "artifacts": []
            }
            """;

        ManifestDocument manifest = ManifestSerializer.Deserialize(json);
        string serialized = ManifestSerializer.Serialize(manifest);
        using JsonDocument document = JsonDocument.Parse(serialized);

        Assert.AreEqual(
            expectedState,
            document.RootElement.GetProperty("protocolResult").GetString());
    }

    [TestMethod]
    public void EvaluateSeal_CompleteUnexpectedEmptyCollection_RemainsInProgress_Issue64410323()
    {
        ManifestDocument manifest = CreateTerminalManifest(new CollectionEvidence(
            CollectionStatus.Complete,
            plannedArtifactCount: 1,
            usableArtifactCount: 0,
            noTrafficExpected: false,
            EvidenceReasonCode.None));

        ManifestSealState actual = manifest.EvaluateSeal();

        Assert.AreEqual(ManifestSealState.InProgress, actual);
    }

    [TestMethod]
    public void EvaluateSeal_UnavailableCollectionWithoutReason_RemainsInProgress_Issue64410323()
    {
        ManifestDocument manifest = CreateTerminalManifest(new CollectionEvidence(
            CollectionStatus.Unavailable,
            plannedArtifactCount: 1,
            usableArtifactCount: 0,
            noTrafficExpected: false,
            EvidenceReasonCode.None));

        ManifestSealState actual = manifest.EvaluateSeal();

        Assert.AreEqual(ManifestSealState.InProgress, actual);
    }

    [DataTestMethod]
    [DataRow(" ")]
    [DataRow(null)]
    public void Seal_InvalidUnresolvedWriterId_RejectsManifest_Issue64410323(string? writerId)
    {
        ManifestDocument manifest = CreateTerminalManifest(new CollectionEvidence(
            CollectionStatus.Complete,
            plannedArtifactCount: 0,
            usableArtifactCount: 0,
            noTrafficExpected: true,
            EvidenceReasonCode.NoTrafficExpected));
        manifest.UnresolvedWriters.Add(writerId!);

        Assert.ThrowsExactly<ManifestSerializationException>(
            () => ManifestSealer.Seal(manifest));
    }

    [DataTestMethod]
    [DataRow("protocolResult")]
    [DataRow("cleanupStatus")]
    [DataRow("finalizationStatus")]
    [DataRow("runnerResult")]
    public void Serialize_FinalManifestWithPendingOutcome_RejectsInconsistentCompletion_Issue64410323(
        string pendingDimension)
    {
        ManifestDocument manifest = CreateTerminalManifest(new CollectionEvidence(
            CollectionStatus.Disabled,
            plannedArtifactCount: 0,
            usableArtifactCount: 0,
            noTrafficExpected: false,
            EvidenceReasonCode.None));

        switch (pendingDimension)
        {
            case "protocolResult":
                manifest.ProtocolResult = ProtocolResultState.Pending;
                break;
            case "cleanupStatus":
                manifest.CleanupStatus = LifecycleStatus.Pending;
                break;
            case "finalizationStatus":
                manifest.FinalizationStatus = LifecycleStatus.Pending;
                break;
            case "runnerResult":
                manifest.RunnerResult = RunnerResultState.Pending;
                break;
            default:
                throw new ArgumentOutOfRangeException(
                    nameof(pendingDimension),
                    pendingDimension,
                    "Unknown manifest outcome dimension.");
        }

        Assert.ThrowsExactly<ManifestSerializationException>(
            () => ManifestSerializer.Serialize(manifest));
    }

    [TestMethod]
    public void Deserialize_FinalManifestWithPendingOutcomes_RejectsInconsistentCompletion_Issue64410323()
    {
        string json = $$"""
            {
              "schemaVersion": "{{ManifestSchema.SupportedVersion}}",
              "collectionStatus": "Disabled",
              "completionState": "Final",
              "artifacts": []
            }
            """;

        Assert.ThrowsExactly<ManifestSerializationException>(
            () => ManifestSerializer.Deserialize(json));
    }

    [DataTestMethod]
    [DataRow("protocolResult")]
    [DataRow("coverageQualification")]
    [DataRow("cleanupStatus")]
    [DataRow("finalizationStatus")]
    [DataRow("runnerResult")]
    [DataRow("completionState")]
    public void Serialize_UndefinedManifestOutcome_RejectsUnsupportedValue_Issue64410323(
        string outcomeDimension)
    {
        ManifestDocument manifest = CreateTerminalManifest(new CollectionEvidence(
            CollectionStatus.Disabled,
            plannedArtifactCount: 0,
            usableArtifactCount: 0,
            noTrafficExpected: false,
            EvidenceReasonCode.None));
        SetUndefinedOutcome(manifest, outcomeDimension);

        Assert.ThrowsExactly<ManifestSerializationException>(
            () => ManifestSerializer.Serialize(manifest));
    }

    [TestMethod]
    public void EvaluateSeal_UndefinedProtocolOutcome_RejectsUnsupportedValue_Issue64410323()
    {
        ManifestDocument manifest = CreateTerminalManifest(new CollectionEvidence(
            CollectionStatus.Disabled,
            plannedArtifactCount: 0,
            usableArtifactCount: 0,
            noTrafficExpected: false,
            EvidenceReasonCode.None));
        manifest.ProtocolResult = (ProtocolResultState)99;

        Assert.ThrowsExactly<ManifestSerializationException>(
            () => manifest.EvaluateSeal());
    }

    [TestMethod]
    public void Seal_UndefinedProtocolOutcome_RejectsUnsupportedValue_Issue64410323()
    {
        ManifestDocument manifest = CreateTerminalManifest(new CollectionEvidence(
            CollectionStatus.Disabled,
            plannedArtifactCount: 0,
            usableArtifactCount: 0,
            noTrafficExpected: false,
            EvidenceReasonCode.None));
        manifest.ProtocolResult = (ProtocolResultState)99;

        Assert.ThrowsExactly<ManifestSerializationException>(
            () => ManifestSealer.Seal(manifest));
    }

    [DataTestMethod]
    [DataRow(EvidenceReasonCode.None, EvidenceReasonCode.UnexpectedEmptyEvidence)]
    [DataRow(EvidenceReasonCode.CollectionGap, EvidenceReasonCode.CollectionGap)]
    public void ValidateForFinalization_PartialWithoutUsableArtifact_NormalizesUnavailable_Issue64410323(
        EvidenceReasonCode sourceReason,
        EvidenceReasonCode expectedReason)
    {
        var collection = new CollectionEvidence(
            CollectionStatus.Partial,
            plannedArtifactCount: 1,
            usableArtifactCount: 0,
            noTrafficExpected: false,
            sourceReason);

        CollectionValidationResult result =
            CollectionEvidenceValidator.ValidateForFinalization(collection);

        Assert.IsTrue(result.CanFinalize);
        Assert.AreEqual(CollectionStatus.Unavailable, result.Status);
        Assert.AreEqual(expectedReason, result.ReasonCode);
    }

    [TestMethod]
    public void ValidateForFinalization_CompleteUnexpectedEmpty_NormalizesUnavailable_Issue64410323()
    {
        var collection = new CollectionEvidence(
            CollectionStatus.Complete,
            plannedArtifactCount: 1,
            usableArtifactCount: 0,
            noTrafficExpected: false,
            EvidenceReasonCode.None);

        CollectionValidationResult result =
            CollectionEvidenceValidator.ValidateForFinalization(collection);

        Assert.IsTrue(result.CanFinalize);
        Assert.AreEqual(CollectionStatus.Unavailable, result.Status);
        Assert.AreEqual(
            EvidenceReasonCode.UnexpectedEmptyEvidence,
            result.ReasonCode);
    }

    [TestMethod]
    public void ValidateForFinalization_PartialWithUsableArtifact_RemainsPartial_Issue64410323()
    {
        var collection = new CollectionEvidence(
            CollectionStatus.Partial,
            plannedArtifactCount: 2,
            usableArtifactCount: 1,
            noTrafficExpected: false,
            EvidenceReasonCode.CollectionGap);

        CollectionValidationResult result =
            CollectionEvidenceValidator.ValidateForFinalization(collection);

        Assert.IsTrue(result.CanFinalize);
        Assert.AreEqual(CollectionStatus.Partial, result.Status);
        Assert.AreEqual(EvidenceReasonCode.CollectionGap, result.ReasonCode);
    }

    private static ManifestDocument CreateTerminalManifest(CollectionEvidence collection)
    {
        return new ManifestDocument(ManifestSchema.SupportedVersion)
        {
            ProtocolResult = ProtocolResultState.Passed,
            Collection = collection,
            CoverageQualification = CoverageQualification.Unverified,
            CleanupStatus = LifecycleStatus.Complete,
            FinalizationStatus = LifecycleStatus.Complete,
            RunnerResult = RunnerResultState.Passed,
            CompletionState = CompletionState.Final,
        };
    }

    private static void SetUndefinedOutcome(
        ManifestDocument manifest,
        string outcomeDimension)
    {
        switch (outcomeDimension)
        {
            case "protocolResult":
                manifest.ProtocolResult = (ProtocolResultState)99;
                break;
            case "coverageQualification":
                manifest.CoverageQualification = (CoverageQualification)99;
                break;
            case "cleanupStatus":
                manifest.CleanupStatus = (LifecycleStatus)99;
                break;
            case "finalizationStatus":
                manifest.FinalizationStatus = (LifecycleStatus)99;
                break;
            case "runnerResult":
                manifest.RunnerResult = (RunnerResultState)99;
                break;
            case "completionState":
                manifest.CompletionState = (CompletionState)99;
                break;
            default:
                throw new ArgumentOutOfRangeException(
                    nameof(outcomeDimension),
                    outcomeDimension,
                    "Unknown manifest outcome dimension.");
        }
    }
}
