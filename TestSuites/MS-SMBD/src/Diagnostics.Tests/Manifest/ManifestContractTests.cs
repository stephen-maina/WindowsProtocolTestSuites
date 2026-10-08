// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Text.Json;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Evidence;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Manifest;

/// <summary>
/// Red tests for the Task 64410323 B01 machine-readable manifest contract.
/// </summary>
[TestClass]
public sealed class ManifestContractTests
{
    [TestMethod]
    public void Serialize_SupportedSchemaVersion_EmitsExplicitVersion_Issue64410323()
    {
        // Arrange
        ManifestDocument manifest = CreateBaselineManifest();

        // Act
        string json = ManifestSerializer.Serialize(manifest);
        using JsonDocument document = JsonDocument.Parse(json);
        string? actualVersion = document.RootElement.GetProperty("schemaVersion").GetString();

        // Assert
        Assert.AreEqual(ManifestSchema.SupportedVersion, actualVersion);
    }

    [TestMethod]
    public void Deserialize_UnsupportedMajorVersion_FailsWithClearVersionDetails_Issue64410323()
    {
        // Arrange
        const string json = """
            {
              "schemaVersion": "2.0",
              "artifacts": []
            }
            """;

        // Act
        UnsupportedSchemaVersionException exception = Assert.ThrowsExactly<UnsupportedSchemaVersionException>(
            () => ManifestSerializer.Deserialize(json));

        // Assert
        Assert.IsTrue(
            exception.Message.Contains("2.0", StringComparison.Ordinal) &&
            exception.Message.Contains(ManifestSchema.SupportedMajorVersion.ToString(), StringComparison.Ordinal),
            "The error must identify both the received schema version and the supported major version.");
    }

    [TestMethod]
    public void Serialize_IndependentOutcomeDimensions_PreservesEveryDimension_Issue64410323()
    {
        // Arrange
        ManifestDocument manifest = CreateBaselineManifest();
        manifest.ProtocolResult = ProtocolResultState.Failed;
        manifest.Collection = new CollectionEvidence(
            CollectionStatus.Partial,
            plannedArtifactCount: 2,
            usableArtifactCount: 1,
            noTrafficExpected: false,
            EvidenceReasonCode.CollectionGap);
        manifest.CoverageQualification = CoverageQualification.Unsupported;
        manifest.CleanupStatus = LifecycleStatus.Failed;
        manifest.FinalizationStatus = LifecycleStatus.Complete;
        manifest.RunnerResult = RunnerResultState.Aborted;
        manifest.CompletionState = CompletionState.Interrupted;

        // Act
        string json = ManifestSerializer.Serialize(manifest);
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        string actual = string.Join(
            "|",
            root.GetProperty("protocolResult").GetString(),
            root.GetProperty("collectionStatus").GetString(),
            root.GetProperty("coverageQualification").GetString(),
            root.GetProperty("cleanupStatus").GetString(),
            root.GetProperty("finalizationStatus").GetString(),
            root.GetProperty("runnerResult").GetString(),
            root.GetProperty("completionState").GetString());

        // Assert
        Assert.AreEqual("Failed|Partial|Unsupported|Failed|Complete|Aborted|Interrupted", actual);
    }

    [TestMethod]
    public void Deserialize_NullArtifactEntry_RejectsPlaceholderArtifact_Issue64410323()
    {
        // Arrange
        string json = $$"""
            {
              "schemaVersion": "{{ManifestSchema.SupportedVersion}}",
              "artifacts": [null]
            }
            """;

        // Act and assert
        Assert.ThrowsExactly<ManifestSerializationException>(() => ManifestSerializer.Deserialize(json));
    }

    [TestMethod]
    public void Serialize_ValidEmptyArtifactInventory_EmitsEmptyArrayWithoutPlaceholder_Issue64410323()
    {
        // Arrange
        ManifestDocument manifest = CreateBaselineManifest();

        // Act
        string json = ManifestSerializer.Serialize(manifest);
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement artifacts = document.RootElement.GetProperty("artifacts");

        // Assert
        Assert.AreEqual(0, artifacts.GetArrayLength());
    }

    [TestMethod]
    public void Serialize_HostileSensitiveMetadata_DoesNotEmitSecretValue_Issue64410323()
    {
        // Arrange
        const string secret = "task-64410323-secret-value";
        ManifestDocument manifest = CreateBaselineManifest();
        manifest.Metadata.Add(new ManifestMetadataEntry(
            "runner.arguments",
            $"diagnostic-tool --token {secret}",
            MetadataSensitivity.Secret));

        // Act
        string json = ManifestSerializer.Serialize(manifest);

        // Assert
        Assert.IsFalse(
            json.Contains(secret, StringComparison.Ordinal),
            "Explicitly sensitive metadata must be omitted or redacted by the B01 manifest boundary.");
    }

    private static ManifestDocument CreateBaselineManifest()
    {
        return new ManifestDocument(ManifestSchema.SupportedVersion)
        {
            ProtocolResult = ProtocolResultState.Pending,
            Collection = new CollectionEvidence(
                CollectionStatus.Disabled,
                plannedArtifactCount: 0,
                usableArtifactCount: 0,
                noTrafficExpected: false,
                EvidenceReasonCode.None),
            CoverageQualification = CoverageQualification.Unverified,
            CleanupStatus = LifecycleStatus.Pending,
            FinalizationStatus = LifecycleStatus.Pending,
            RunnerResult = RunnerResultState.Pending,
            CompletionState = CompletionState.Provisional,
        };
    }
}