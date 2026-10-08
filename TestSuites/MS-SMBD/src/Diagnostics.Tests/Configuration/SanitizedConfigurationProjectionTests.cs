// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Configuration;

[TestClass]
public sealed class SanitizedConfigurationProjectionTests
{
    [TestMethod]
    public void Create_EnabledConfiguration_UsesB01SensitivityAndOmitsUnallowlistedSecrets_Issue64410334()
    {
        Dictionary<string, string?> values =
            DiagnosticsConfigurationReaderTests.CreateValidValues(
                includeExplicitSelections: true);
        values[DiagnosticsConfigurationPropertyNames.ToolPath] =
            @"C:\Program Files\Capture Tool\capture.exe";
        const string Secret = "NeverPersistThisPassword";
        values["SutPassword"] = Secret;
        var source = new TestEffectiveConfigurationSource(values);
        var errors = new DiagnosticErrorLedger();
        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(
                source,
                errors,
                DateTimeOffset.Parse("2026-10-02T16:00:00Z"),
                new DiagnosticsConfigurationPolicy(new[] { "Dumpcap" }));

        IReadOnlyList<ManifestMetadataEntry> metadata =
            SanitizedConfigurationProjection.Create(configuration);
        var manifest = new ManifestDocument(ManifestSchema.SupportedVersion);
        manifest.Metadata.AddRange(metadata);
        string json = ManifestSerializer.Serialize(manifest);

        Assert.AreEqual(
            MetadataSensitivity.Sensitive,
            metadata.Single(
                entry => entry.Key == DiagnosticsConfigurationPropertyNames.ArtifactRoot)
                .Sensitivity);
        Assert.AreEqual(
            MetadataSensitivity.Sensitive,
            metadata.Single(
                entry => entry.Key == DiagnosticsConfigurationPropertyNames.ToolPath)
                .Sensitivity);
        Assert.AreEqual(
            MetadataSensitivity.Sensitive,
            metadata.Single(
                entry => entry.Key == DiagnosticsConfigurationPropertyNames.Targets)
                .Sensitivity);
        Assert.IsFalse(json.Contains(@"C:\rdma-evidence", StringComparison.Ordinal));
        Assert.IsFalse(json.Contains("10.20.30.40", StringComparison.Ordinal));
        Assert.IsFalse(json.Contains("capture.exe", StringComparison.Ordinal));
        Assert.IsFalse(json.Contains(Secret, StringComparison.Ordinal));
        Assert.IsFalse(json.Contains("SutPassword", StringComparison.Ordinal));
        StringAssert.Contains(json, ManifestMetadataEntry.DefaultRedactionMarker);
    }

    [TestMethod]
    public void Create_EnabledConfiguration_RecordsConfiguredAndInferredProvenanceSeparately_Issue64410334()
    {
        var source = new TestEffectiveConfigurationSource(
            DiagnosticsConfigurationReaderTests.CreateValidValues(
                includeExplicitSelections: false));
        var errors = new DiagnosticErrorLedger();
        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(
                source,
                errors,
                DateTimeOffset.Parse("2026-10-02T16:00:00Z"),
                SmbdDiagnosticsConfigurationProperties.PropertyMap);

        IReadOnlyDictionary<string, string?> projection =
            SanitizedConfigurationProjection.Create(configuration)
                .Where(entry => entry.Sensitivity == MetadataSensitivity.NonSensitive)
                .ToDictionary(entry => entry.Key, entry => entry.Value);

        Assert.AreEqual(
            "Configured",
            projection[
                DiagnosticsConfigurationPropertyNames.ArtifactRoot +
                SanitizedConfigurationProjection.ProvenanceSuffix]);
        Assert.AreEqual(
            "Inferred",
            projection[
                DiagnosticsConfigurationPropertyNames.Provider +
                SanitizedConfigurationProjection.ProvenanceSuffix]);
        Assert.AreEqual(
            "Inferred",
            projection[
                DiagnosticsConfigurationPropertyNames.Targets +
                SanitizedConfigurationProjection.ProvenanceSuffix]);
    }

    [TestMethod]
    public void Create_DisabledConfiguration_ProjectsOnlyDisabledState_Issue64410334()
    {
        var source = new TestEffectiveConfigurationSource(
            new Dictionary<string, string?>());
        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(
                source,
                new DiagnosticErrorLedger(),
                DateTimeOffset.Parse("2026-10-02T16:00:00Z"));

        IReadOnlyList<ManifestMetadataEntry> metadata =
            SanitizedConfigurationProjection.Create(configuration);

        Assert.AreEqual(2, metadata.Count);
        Assert.AreEqual(
            DiagnosticsConfigurationPropertyNames.Enabled,
            metadata[0].Key);
        Assert.AreEqual("false", metadata[0].Value);
        Assert.AreEqual(
            DiagnosticsConfigurationPropertyNames.Enabled +
            SanitizedConfigurationProjection.ProvenanceSuffix,
            metadata[1].Key);
        Assert.AreEqual("Inferred", metadata[1].Value);
    }

    [TestMethod]
    public void Create_UnparsableEnabled_ProjectsFalseInferredRatherThanConfiguredTrue_Issue64410334()
    {
        var source = new TestEffectiveConfigurationSource(
            new Dictionary<string, string?>
            {
                [DiagnosticsConfigurationPropertyNames.Enabled] = "sometimes",
            });
        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(
                source,
                new DiagnosticErrorLedger(),
                DateTimeOffset.Parse("2026-10-02T16:00:00Z"));

        IReadOnlyList<ManifestMetadataEntry> metadata =
            SanitizedConfigurationProjection.Create(configuration);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsFalse(configuration.Enabled);
        Assert.AreEqual(2, metadata.Count);
        Assert.AreEqual("false", metadata[0].Value);
        Assert.AreEqual("Inferred", metadata[1].Value);
    }

    [TestMethod]
    public void Create_InvalidHostileConfiguration_ProjectsNoHostileRawValues_INV_B16_INV_B17_Issue64410334()
    {
        const string HostileArtifactRoot = @"C:\Evidence\*";
        const string HostileTargets = "Adapter-A\u0001";
        Dictionary<string, string?> values =
            DiagnosticsConfigurationReaderTests.CreateValidValues(
                includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ArtifactRoot] =
            HostileArtifactRoot;
        values[DiagnosticsConfigurationPropertyNames.Targets] =
            HostileTargets;
        var errors = new DiagnosticErrorLedger();
        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                DateTimeOffset.Parse("2026-10-05T22:00:00Z"));

        IReadOnlyList<ManifestMetadataEntry> metadata =
            SanitizedConfigurationProjection.Create(configuration);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.AreEqual(2, metadata.Count);
        Assert.IsFalse(
            metadata.Any(
                entry =>
                    entry.Value?.Contains(
                        HostileArtifactRoot,
                        StringComparison.Ordinal) == true));
        Assert.IsFalse(
            metadata.Any(
                entry =>
                    entry.Value?.Contains(
                        HostileTargets,
                        StringComparison.Ordinal) == true));
        Assert.IsFalse(
            errors.Chronology.Any(
                error =>
                    error.Message.Contains(
                        HostileArtifactRoot,
                        StringComparison.Ordinal) ||
                    error.Message.Contains(
                        HostileTargets,
                        StringComparison.Ordinal)));
    }

    [DataTestMethod]
    [DataRow("Add")]
    [DataRow("Clear")]
    [DataRow("Remove")]
    [DataRow("Replace")]
    public void Create_ReturnsStructurallyReadOnlySnapshot_INV_B23_Issue64410334(
        string operation)
    {
        var source = new TestEffectiveConfigurationSource(
            new Dictionary<string, string?>());
        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(
                source,
                new DiagnosticErrorLedger(),
                DateTimeOffset.Parse("2026-10-05T23:00:00Z"));
        IReadOnlyList<ManifestMetadataEntry> metadata =
            SanitizedConfigurationProjection.Create(configuration);
        IList<ManifestMetadataEntry> list =
            metadata as IList<ManifestMetadataEntry> ??
            throw new AssertFailedException(
                "The projection must expose supported read-only list semantics.");
        int originalCount = metadata.Count;
        ManifestMetadataEntry originalFirst = metadata[0];

        Assert.ThrowsExactly<NotSupportedException>(
            () =>
            {
                switch (operation)
                {
                    case "Add":
                        list.Add(originalFirst);
                        break;
                    case "Clear":
                        list.Clear();
                        break;
                    case "Remove":
                        list.RemoveAt(0);
                        break;
                    case "Replace":
                        list[0] = originalFirst;
                        break;
                    default:
                        throw new AssertFailedException(
                            $"Unknown mutation operation '{operation}'.");
                }
            });

        Assert.IsTrue(list.IsReadOnly);
        Assert.AreEqual(originalCount, metadata.Count);
        Assert.AreSame(originalFirst, metadata[0]);
    }
}
