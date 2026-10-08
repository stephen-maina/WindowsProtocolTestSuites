// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Diagnostics.Manifest;
using Microsoft.Protocols.TestSuites.Diagnostics.Providers;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Configuration;

[TestClass]
public sealed class DiagnosticsConfigurationReaderTests
{
    private const string SecretSentinel = "must-not-be-read";

    private static readonly DateTimeOffset OccurredAt =
        DateTimeOffset.Parse("2026-10-02T16:00:00Z");

    [DataTestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("false")]
    [DataRow(" FALSE ")]
    public void Read_Disabled_DoesNotReadCapturePolicyOrCreateErrors_Issue64410334(
        string? enabled)
    {
        var source = new TestEffectiveConfigurationSource(
            CreateMalformedDisabledValues(enabled));
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(source, errors, OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Disabled,
            configuration.State);
        Assert.IsFalse(configuration.Enabled);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationPropertyNames.Enabled },
            source.RequestedProperties);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [DataTestMethod]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\..\Evidence")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\..\..\Final")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"C:\..\Tools\capture.exe")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"C:\Tools\..\..\capture.exe")]
    public void Read_ConcreteLocalPath_RejectsAboveRootTraversalWithoutInventoryOrLeak_INV_B22_Issue64410334(
        string propertyName,
        string configuredPath)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[propertyName] = configuredPath;
        var readerErrors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                readerErrors,
                OccurredAt);
        bool inventoryEnumerated = false;
        var resolutionErrors = new DiagnosticErrorLedger();
        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                inventoryEnumerated = true;
                return Array.Empty<CaptureAdapterObservation>();
            },
            resolutionErrors,
            OccurredAt);
        IReadOnlyList<ManifestMetadataEntry> projection =
            SanitizedConfigurationProjection.Create(configuration);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsFalse(inventoryEnumerated);
        Assert.IsFalse(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationErrorCodes.InvalidValue },
            readerErrors.Chronology.Select(error => error.Code).ToArray());
        Assert.AreEqual(0, resolutionErrors.Chronology.Count);
        Assert.IsFalse(
            readerErrors.Chronology.Any(
                error => error.Message.Contains(
                    configuredPath,
                    StringComparison.Ordinal)));
        Assert.IsFalse(
            projection.Any(
                entry =>
                    entry.Value?.Contains(
                        configuredPath,
                        StringComparison.Ordinal) == true));
    }

    [TestMethod]
    public void Read_EnabledWithCanonicalValues_AppliesExplicitDefaultsAndProvenance_Issue64410334()
    {
        var source = new TestEffectiveConfigurationSource(
            CreateValidValues(includeExplicitSelections: false));
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(source, errors, OccurredAt);
        DiagnosticsCaptureConfiguration capture =
            configuration.Capture ??
            throw new AssertFailedException("Enabled configuration requires capture settings.");
        ProvenancedValue<bool> nativeLogs =
            configuration.NativeLogsEnabled ??
            throw new AssertFailedException("Enabled configuration requires native-log policy.");
        ProvenancedValue<DiagnosticsRetentionPolicy> retention =
            configuration.Retention ??
            throw new AssertFailedException("Enabled configuration requires retention policy.");

        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.IsTrue(configuration.Enabled);
        Assert.AreEqual(@"C:\rdma-evidence", configuration.ArtifactRoot?.Value);
        Assert.AreEqual(
            ConfigurationProvenance.Configured,
            configuration.ArtifactRoot?.Provenance);
        Assert.AreEqual("Automatic", capture.Provider.Value);
        Assert.AreEqual(
            ConfigurationProvenance.Inferred,
            capture.Provider.Provenance);
        Assert.AreEqual(
            "10.20.30.40",
            capture.Targets.Single().Value);
        Assert.AreEqual(
            ConfigurationProvenance.Inferred,
            capture.Targets.Single().Provenance);
        Assert.AreEqual(
            CaptureTrafficScope.RdmaFocused,
            capture.TrafficScope.Value);
        Assert.AreEqual(
            CaptureFileFormat.Native,
            capture.Format.Value);
        Assert.AreEqual(
            DiagnosticsRetentionPolicy.KeepAll,
            retention.Value);
        Assert.IsFalse(nativeLogs.Value);
        Assert.AreEqual(TimeSpan.FromSeconds(5), capture.StartTimeout.Value);
        Assert.AreEqual(TimeSpan.FromSeconds(10), capture.StopTimeout.Value);
        Assert.AreEqual(TimeSpan.FromMinutes(2), capture.MaxDuration.Value);
        Assert.AreEqual(1048576L, capture.MaxBytes.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
        CollectionAssert.DoesNotContain(
            source.RequestedProperties,
            "SutPassword");
    }

    [TestMethod]
    public void Read_ExplicitSelections_CanonicalizesAllowlistedValuesAndTargets_Issue64410334()
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: true);
        var source = new TestEffectiveConfigurationSource(values);
        var errors = new DiagnosticErrorLedger();
        var policy = new DiagnosticsConfigurationPolicy(
            new[] { "Dumpcap", "MellanoxSniffer" });

        DiagnosticsConfiguration configuration =
            Read(
                source,
                errors,
                OccurredAt,
                policy);
        DiagnosticsCaptureConfiguration capture =
            configuration.Capture ??
            throw new AssertFailedException("Enabled configuration requires capture settings.");
        ProvenancedValue<bool> nativeLogs =
            configuration.NativeLogsEnabled ??
            throw new AssertFailedException("Enabled configuration requires native-log policy.");

        Assert.AreEqual("Dumpcap", capture.Provider.Value);
        Assert.AreEqual(
            ConfigurationProvenance.Configured,
            capture.Provider.Provenance);
        CollectionAssert.AreEqual(
            new[] { "10.20.30.40", "Adapter-B" },
            capture.Targets
                .Select(target => target.Value)
                .ToArray());
        Assert.IsTrue(
            capture.Targets.All(
                target => target.Provenance == ConfigurationProvenance.Configured));
        Assert.AreEqual(
            CaptureTrafficScope.Broader,
            capture.TrafficScope.Value);
        Assert.IsTrue(nativeLogs.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public void Read_PaddedValidNonPathValues_TrimsOnce_INV_B18_Issue64410334()
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.Enabled] = " true ";
        values[DiagnosticsConfigurationPropertyNames.Provider] = " dumpCAP ";
        values[DiagnosticsConfigurationPropertyNames.Targets] =
            " 10.20.30.40 ; Adapter-B ";
        values[DiagnosticsConfigurationPropertyNames.TrafficScope] =
            " broader ";
        values[DiagnosticsConfigurationPropertyNames.StartTimeout] =
            " 00:00:05 ";
        values[DiagnosticsConfigurationPropertyNames.StopTimeout] =
            " 00:00:10 ";
        values[DiagnosticsConfigurationPropertyNames.MaxDuration] =
            " 00:02:00 ";
        values[DiagnosticsConfigurationPropertyNames.MaxBytes] =
            " 1048576 ";
        values[DiagnosticsConfigurationPropertyNames.Format] = " native ";
        values[DiagnosticsConfigurationPropertyNames.NativeLogsEnabled] =
            " true ";
        values[DiagnosticsConfigurationPropertyNames.Retention] =
            " keepall ";
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt,
                new DiagnosticsConfigurationPolicy(new[] { "Dumpcap" }));
        DiagnosticsCaptureConfiguration capture =
            configuration.Capture ??
            throw new AssertFailedException(
                "Enabled configuration requires capture settings.");

        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.AreEqual("Dumpcap", capture.Provider.Value);
        CollectionAssert.AreEqual(
            new[] { "10.20.30.40", "Adapter-B" },
            capture.Targets.Select(target => target.Value).ToArray());
        Assert.AreEqual(CaptureTrafficScope.Broader, capture.TrafficScope.Value);
        Assert.AreEqual(TimeSpan.FromSeconds(5), capture.StartTimeout.Value);
        Assert.AreEqual(TimeSpan.FromSeconds(10), capture.StopTimeout.Value);
        Assert.AreEqual(TimeSpan.FromMinutes(2), capture.MaxDuration.Value);
        Assert.AreEqual(1048576L, capture.MaxBytes.Value);
        Assert.AreEqual(CaptureFileFormat.Native, capture.Format.Value);
        Assert.IsTrue(configuration.NativeLogsEnabled?.Value);
        Assert.AreEqual(
            DiagnosticsRetentionPolicy.KeepAll,
            configuration.Retention?.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [DataTestMethod]
    [DataRow("4")]
    [DataRow("10.1")]
    [DataRow("RDMA-A")]
    public void Read_NonFullIpSelector_PreservesExactIdentifierToken_Issue64410334(
        string selector)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.Targets] = selector;
        var source = new TestEffectiveConfigurationSource(values);
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(source, errors, OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.AreEqual(
            selector,
            configuration.Capture?.Targets.Single().Value);
        Assert.AreEqual(0, errors.Chronology.Count);
        CollectionAssert.DoesNotContain(
            source.RequestedProperties,
            "SutPassword");
    }

    [DataTestMethod]
    [DataRow("10.20.30.40", "10.20.30.40")]
    [DataRow("2001:0db8:0:0:0:0:0:1", "2001:db8::1")]
    public void Read_UnambiguousFullIpSelector_CanonicalizesAddress_Issue64410334(
        string selector,
        string expectedCanonicalSelector)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.Targets] = selector;
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.AreEqual(
            expectedCanonicalSelector,
            configuration.Capture?.Targets.Single().Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public void ReadAndResolve_InferredLegacyAbbreviatedIpv4_DoesNotSelectCanonicalLookalike_INV_B15_Issue64410334()
    {
        const string Selector = "10.1";
        const string CanonicalLookalike = "10.0.0.1";
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[SmbdDiagnosticsConfigurationProperties.ClientRNicIp] = Selector;
        var source = new TestEffectiveConfigurationSource(values);
        var readerErrors = new DiagnosticErrorLedger();
        DiagnosticsConfiguration configuration =
            Read(
                source,
                readerErrors,
                OccurredAt);
        bool inventoryEnumerated = false;
        var resolutionErrors = new DiagnosticErrorLedger();

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                inventoryEnumerated = true;
                return new[]
                {
                    new CaptureAdapterObservation(
                        stableIdentifier: "stable-10-0-0-1",
                        interfaceName: "RDMA-Lookalike",
                        providerSelector: "99",
                        addresses: new[] { CanonicalLookalike },
                        isConnected: true,
                        physicalAdapterIdentifier: "PCI\\VEN_15B3&DEV_101D",
                        driverIdentity: "mlx5.sys 25.1.0"),
                };
            },
            resolutionErrors,
            OccurredAt);

        Assert.IsTrue(inventoryEnumerated);
        Assert.IsFalse(
            resolution.IsSuccessful,
            "The inferred abbreviated token must not select its permissively canonicalized IPv4 lookalike.");
        Assert.AreEqual(0, resolution.Targets.Count);
        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.AreEqual(
            Selector,
            configuration.Capture?.Targets.Single().Value);
        Assert.AreEqual(
            ConfigurationProvenance.Inferred,
            configuration.Capture?.Targets.Single().Provenance);
        Assert.AreEqual(0, readerErrors.Chronology.Count);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationErrorCodes.TargetNotFound },
            resolutionErrors.Chronology
                .Select(error => error.Code)
                .ToArray());
        foreach (string value in new[]
                 {
                     Selector,
                     CanonicalLookalike,
                     SecretSentinel,
                 })
        {
            Assert.IsFalse(
                resolutionErrors.Chronology.Any(
                    error => error.Message.Contains(
                        value,
                        StringComparison.Ordinal)));
        }
    }

    [DataTestMethod]
    [DataRow("fe80::1%12", true)]
    [DataRow("[fe80::1]:443", true)]
    [DataRow("fe80::1%12", false)]
    [DataRow("[fe80::1]:443", false)]
    public void Read_DecoratedIpv6Selector_ReturnsInvalidWithoutFallbackInventoryOrLeak_INV_B19_Issue64410334(
        string selector,
        bool explicitTarget)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        if (explicitTarget)
        {
            values[DiagnosticsConfigurationPropertyNames.Targets] = selector;
        }
        else
        {
            values.Remove(DiagnosticsConfigurationPropertyNames.Targets);
            values[SmbdDiagnosticsConfigurationProperties.ClientRNicIp] =
                selector;
        }

        var source = new TestEffectiveConfigurationSource(values);
        var readerErrors = new DiagnosticErrorLedger();
        DiagnosticsConfiguration configuration =
            Read(
                source,
                readerErrors,
                OccurredAt);
        bool inventoryEnumerated = false;
        var resolutionErrors = new DiagnosticErrorLedger();

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                inventoryEnumerated = true;
                return Array.Empty<CaptureAdapterObservation>();
            },
            resolutionErrors,
            OccurredAt);
        IReadOnlyList<ManifestMetadataEntry> projection =
            SanitizedConfigurationProjection.Create(configuration);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsNull(configuration.Capture);
        if (explicitTarget)
        {
            CollectionAssert.DoesNotContain(
                source.RequestedProperties,
                SmbdDiagnosticsConfigurationProperties.ClientRNicIp);
        }

        Assert.IsFalse(inventoryEnumerated);
        Assert.IsFalse(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationErrorCodes.InvalidValue },
            readerErrors.Chronology.Select(error => error.Code).ToArray());
        Assert.AreEqual(0, resolutionErrors.Chronology.Count);
        Assert.IsFalse(
            readerErrors.Chronology.Any(
                error => error.Message.Contains(
                    selector,
                    StringComparison.Ordinal)));
        Assert.IsFalse(
            projection.Any(
                entry =>
                    entry.Value?.Contains(
                        selector,
                        StringComparison.Ordinal) == true));
    }

    [TestMethod]
    public void ReadAndResolve_InferredNumericSelector_RemainsExactAndDoesNotSelectIpv4Lookalike_INV_B15_Issue64410334()
    {
        const string Selector = "4";
        const string ExpectedStableIdentifier = "stable-provider-4";
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[SmbdDiagnosticsConfigurationProperties.ClientRNicIp] = Selector;
        var readerErrors = new DiagnosticErrorLedger();
        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                readerErrors,
                OccurredAt);
        var resolutionErrors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            new CaptureAdapterObservation(
                stableIdentifier: ExpectedStableIdentifier,
                interfaceName: "RDMA-Index-4",
                providerSelector: Selector,
                addresses: new[] { "10.20.30.40" },
                isConnected: true,
                physicalAdapterIdentifier: "PCI\\VEN_15B3&DEV_101D",
                driverIdentity: "mlx5.sys 25.1.0"),
            new CaptureAdapterObservation(
                stableIdentifier: "stable-ipv4-lookalike",
                interfaceName: "IPv4-Lookalike",
                providerSelector: "99",
                addresses: new[] { "0.0.0.4" },
                isConnected: true,
                physicalAdapterIdentifier: "PCI\\VEN_15B3&DEV_101E",
                driverIdentity: "mlx5.sys 25.1.0"),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            resolutionErrors,
            OccurredAt);

        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(
            ExpectedStableIdentifier,
            resolution.Targets.Single().StableIdentifier.Value,
            "The inferred numeric token must resolve as an exact identifier, not as abbreviated IPv4.");
        Assert.AreEqual(
            Selector,
            configuration.Capture?.Targets.Single().Value);
        Assert.AreEqual(
            ConfigurationProvenance.Inferred,
            configuration.Capture?.Targets.Single().Provenance);
        Assert.AreEqual(0, readerErrors.Chronology.Count);
        Assert.AreEqual(0, resolutionErrors.Chronology.Count);
    }

    [DataTestMethod]
    [DataRow("192.0.2.10", "192.0.2.10")]
    [DataRow("2001:0db8:0:0:0:0:0:1", "2001:db8::1")]
    public void ReadAndResolve_InferredFullIpSelector_CanonicalizesAndResolves_INV_B15_Issue64410334(
        string selector,
        string expectedCanonicalSelector)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[SmbdDiagnosticsConfigurationProperties.ClientRNicIp] = selector;
        var readerErrors = new DiagnosticErrorLedger();
        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                readerErrors,
                OccurredAt);
        var resolutionErrors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            new CaptureAdapterObservation(
                stableIdentifier: "stable-full-ip",
                interfaceName: "RDMA-Full-IP",
                providerSelector: "full-ip",
                addresses: new[] { expectedCanonicalSelector },
                isConnected: true,
                physicalAdapterIdentifier: "PCI\\VEN_15B3&DEV_101D",
                driverIdentity: "mlx5.sys 25.1.0"),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            resolutionErrors,
            OccurredAt);

        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(
            expectedCanonicalSelector,
            configuration.Capture?.Targets.Single().Value);
        Assert.AreEqual(
            ConfigurationProvenance.Inferred,
            configuration.Capture?.Targets.Single().Provenance);
        Assert.AreEqual(0, readerErrors.Chronology.Count);
        Assert.AreEqual(0, resolutionErrors.Chronology.Count);
    }

    [TestMethod]
    public void Read_InferredControlCharacterSelector_ReturnsInvalidWithoutEnumerationOrLeak_INV_B15_Issue64410334()
    {
        const string Selector = "10.20.30.40\u0001";
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[SmbdDiagnosticsConfigurationProperties.ClientRNicIp] = Selector;
        var readerErrors = new DiagnosticErrorLedger();
        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                readerErrors,
                OccurredAt);
        bool inventoryEnumerated = false;
        var resolutionErrors = new DiagnosticErrorLedger();

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                inventoryEnumerated = true;
                return Array.Empty<CaptureAdapterObservation>();
            },
            resolutionErrors,
            OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsNull(configuration.Capture);
        Assert.IsFalse(inventoryEnumerated);
        Assert.IsFalse(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationErrorCodes.InvalidValue },
            readerErrors.Chronology
                .Select(error => error.Code)
                .ToArray());
        Assert.AreEqual(0, resolutionErrors.Chronology.Count);
        foreach (string value in new[] { Selector, SecretSentinel })
        {
            Assert.IsFalse(
                readerErrors.Chronology.Any(
                    error => error.Message.Contains(
                        value,
                        StringComparison.Ordinal)));
        }
    }

    [DataTestMethod]
    [DataRow("   ")]
    [DataRow("\t")]
    [DataRow("\r\n")]
    [DataRow("\u0001")]
    [DataRow(" true\u0001")]
    public void Read_MalformedPresentEnabled_ReturnsInvalidWithoutReadingOtherProperties_INV_B16_Issue64410334(
        string malformedValue)
    {
        var source = new TestEffectiveConfigurationSource(
            new Dictionary<string, string?>
            {
                [DiagnosticsConfigurationPropertyNames.Enabled] = malformedValue,
                [DiagnosticsConfigurationPropertyNames.ArtifactRoot] =
                    SecretSentinel,
            });
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(source, errors, OccurredAt);
        var projection = SanitizedConfigurationProjection.Create(configuration);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsFalse(configuration.Enabled);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationPropertyNames.Enabled },
            source.RequestedProperties);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationErrorCodes.InvalidValue },
            errors.Chronology.Select(error => error.Code).ToArray());
        Assert.IsFalse(
            errors.Chronology.Any(
                error => error.Message.Contains(
                    malformedValue,
                    StringComparison.Ordinal)));
        Assert.IsFalse(
            projection.Any(
                entry =>
                    entry.Value?.Contains(
                        malformedValue,
                        StringComparison.Ordinal) == true));
    }

    [DataTestMethod]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot)]
    [DataRow(DiagnosticsConfigurationPropertyNames.Provider)]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath)]
    [DataRow(DiagnosticsConfigurationPropertyNames.TrafficScope)]
    [DataRow(DiagnosticsConfigurationPropertyNames.StartTimeout)]
    [DataRow(DiagnosticsConfigurationPropertyNames.StopTimeout)]
    [DataRow(DiagnosticsConfigurationPropertyNames.MaxDuration)]
    [DataRow(DiagnosticsConfigurationPropertyNames.MaxBytes)]
    [DataRow(DiagnosticsConfigurationPropertyNames.Format)]
    [DataRow(DiagnosticsConfigurationPropertyNames.NativeLogsEnabled)]
    [DataRow(DiagnosticsConfigurationPropertyNames.Retention)]
    public void Read_MalformedPresentScalar_ReturnsInvalidInsteadOfDefaultOrMissing_INV_B16_Issue64410334(
        string propertyName)
    {
        foreach (string malformedValue in new[] { "\t", "\u0001" })
        {
            Dictionary<string, string?> values =
                CreateValidValues(includeExplicitSelections: false);
            values[propertyName] = malformedValue;
            var errors = new DiagnosticErrorLedger();

            DiagnosticsConfiguration configuration =
                Read(
                    new TestEffectiveConfigurationSource(values),
                    errors,
                    OccurredAt);
            var projection =
                SanitizedConfigurationProjection.Create(configuration);

            Assert.AreEqual(
                DiagnosticsConfigurationState.Invalid,
                configuration.State,
                $"{propertyName} must reject a malformed-present value.");
            CollectionAssert.AreEqual(
                new[] { DiagnosticsConfigurationErrorCodes.InvalidValue },
                errors.Chronology.Select(error => error.Code).ToArray(),
                $"{propertyName} must be invalid, not absent or unsupported.");
            Assert.IsFalse(
                errors.Chronology.Any(
                    error => error.Message.Contains(
                        malformedValue,
                        StringComparison.Ordinal)));
            Assert.IsFalse(
                projection.Any(
                    entry =>
                        entry.Value?.Contains(
                            malformedValue,
                            StringComparison.Ordinal) == true));
        }
    }

    [DataTestMethod]
    [DataRow("   ")]
    [DataRow("\t")]
    [DataRow("\r\n")]
    [DataRow("\u0001")]
    [DataRow("Adapter-A\u0001")]
    public void Read_MalformedPresentExplicitTargets_DoesNotReadFallbackOrEnumerateInventory_INV_B16_Issue64410334(
        string malformedTargets)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.Targets] =
            malformedTargets;
        var source = new TestEffectiveConfigurationSource(values);
        var readerErrors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                source,
                readerErrors,
                OccurredAt);
        bool inventoryEnumerated = false;
        var resolutionErrors = new DiagnosticErrorLedger();
        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                inventoryEnumerated = true;
                return Array.Empty<CaptureAdapterObservation>();
            },
            resolutionErrors,
            OccurredAt);
        var projection = SanitizedConfigurationProjection.Create(configuration);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        CollectionAssert.DoesNotContain(
            source.RequestedProperties,
            SmbdDiagnosticsConfigurationProperties.ClientRNicIp);
        Assert.IsFalse(inventoryEnumerated);
        Assert.IsFalse(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationErrorCodes.InvalidValue },
            readerErrors.Chronology.Select(error => error.Code).ToArray());
        Assert.AreEqual(0, resolutionErrors.Chronology.Count);
        Assert.IsFalse(
            readerErrors.Chronology.Any(
                error => error.Message.Contains(
                    malformedTargets,
                    StringComparison.Ordinal)));
        Assert.IsFalse(
            projection.Any(
                entry =>
                    entry.Value?.Contains(
                        malformedTargets,
                        StringComparison.Ordinal) == true));
    }

    [DataTestMethod]
    [DataRow(null)]
    [DataRow("")]
    public void Read_AbsentOrEmptyExplicitTargets_UsesClientRNicIpFallback_INV_B16_Issue64410334(
        string? explicitTargets)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.Targets] =
            explicitTargets;
        var source = new TestEffectiveConfigurationSource(values);
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(source, errors, OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.AreEqual(
            "10.20.30.40",
            configuration.Capture?.Targets.Single().Value);
        Assert.AreEqual(
            ConfigurationProvenance.Inferred,
            configuration.Capture?.Targets.Single().Provenance);
        Assert.AreEqual(
            1,
            source.RequestedProperties.Count(
                property =>
                    property ==
                    SmbdDiagnosticsConfigurationProperties.ClientRNicIp));
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [DataTestMethod]
    [DataRow("   ")]
    [DataRow("\t")]
    [DataRow("\r\n")]
    [DataRow("\u0001")]
    [DataRow("10.20.30.40\u0001")]
    public void Read_MalformedPresentClientRNicIp_IsInvalidNotMissingAndDoesNotEnumerateInventory_INV_B16_Issue64410334(
        string malformedFallback)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values.Remove(DiagnosticsConfigurationPropertyNames.Targets);
        values[SmbdDiagnosticsConfigurationProperties.ClientRNicIp] =
            malformedFallback;
        var readerErrors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                readerErrors,
                OccurredAt);
        bool inventoryEnumerated = false;
        var resolutionErrors = new DiagnosticErrorLedger();
        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                inventoryEnumerated = true;
                return Array.Empty<CaptureAdapterObservation>();
            },
            resolutionErrors,
            OccurredAt);
        var projection = SanitizedConfigurationProjection.Create(configuration);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsFalse(inventoryEnumerated);
        Assert.IsFalse(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationErrorCodes.InvalidValue },
            readerErrors.Chronology.Select(error => error.Code).ToArray());
        Assert.AreEqual(0, resolutionErrors.Chronology.Count);
        Assert.IsFalse(
            readerErrors.Chronology.Any(
                error => error.Message.Contains(
                    malformedFallback,
                    StringComparison.Ordinal)));
        Assert.IsFalse(
            projection.Any(
                entry =>
                    entry.Value?.Contains(
                        malformedFallback,
                        StringComparison.Ordinal) == true));
    }

    [DataTestMethod]
    [DataRow(null)]
    [DataRow("")]
    public void Read_AbsentOrEmptyClientRNicIp_ReturnsMissing_INV_B16_Issue64410334(
        string? fallback)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values.Remove(DiagnosticsConfigurationPropertyNames.Targets);
        values[SmbdDiagnosticsConfigurationProperties.ClientRNicIp] = fallback;
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationErrorCodes.MissingValue },
            errors.Chronology.Select(error => error.Code).ToArray());
    }

    [DataTestMethod]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\*")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\run*\capture")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\run?")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\bad<name")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\bad>name")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\bad""name")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\bad|name")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\file:stream")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\CON")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\nul.txt")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\COM1.log")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\LPT9")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        "C:\\Evidence\\COM\u00B9.log")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        "C:\\Evidence\\LPT\u00B2")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\Evidence\trailing.")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        "C:\\Evidence\\trailing ")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        "C:\\Evidence\\bad\u0001name")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"C:\Tools\*.exe")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"C:\Tools\run*\capture.exe")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"C:\Tools\capture?.exe")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"C:\Tools\bad<name.exe")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"C:\Tools\capture.exe:stream")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"C:\Tools\CON.exe")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"C:\Tools\capture.exe.")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        "C:\\Tools\\capture.exe ")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        "C:\\Tools\\bad\u0001name.exe")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        " C:\\Evidence")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        "C:\\Evidence ")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        " C:\\Tools\\capture.exe")]
    public void Read_ConcreteLocalPath_RejectsUnsafeComponentsAndOuterWhitespace_INV_B17_Issue64410334(
        string propertyName,
        string unsafePath)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[propertyName] = unsafePath;
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt);
        var projection = SanitizedConfigurationProjection.Create(configuration);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code ==
                    DiagnosticsConfigurationErrorCodes.InvalidValue));
        Assert.IsFalse(
            errors.Chronology.Any(
                error => error.Message.Contains(
                    unsafePath,
                    StringComparison.Ordinal)));
        Assert.IsFalse(
            projection.Any(
                entry =>
                    entry.Value?.Contains(
                        unsafePath,
                        StringComparison.Ordinal) == true));
    }

    [DataTestMethod]
    [DataRow(@"C:\", @"C:\")]
    [DataRow(@"C:\Evidence", @"C:\Evidence")]
    [DataRow(@"C:\Evidence\", @"C:\Evidence")]
    [DataRow(
        @"C:\Evidence\run\..\final",
        @"C:\Evidence\final")]
    [DataRow(
        @"C:/Evidence\run/../final",
        @"C:\Evidence\final")]
    public void Read_ConcreteLocalArtifactRoot_AcceptsAndCanonicalizesNeighbors_INV_B17_Issue64410334(
        string configuredPath,
        string expectedPath)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ArtifactRoot] =
            configuredPath;
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.AreEqual(expectedPath, configuration.ArtifactRoot?.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [DataTestMethod]
    [DataRow(@"C:\Tools\capture.exe", @"C:\Tools\capture.exe")]
    [DataRow(@"C:\Tools\CAPTURE.EXE", @"C:\Tools\CAPTURE.EXE")]
    [DataRow(
        @"C:\Tools\bin\..\capture.exe",
        @"C:\Tools\capture.exe")]
    [DataRow(
        @"C:/Tools\bin/../capture.exe",
        @"C:\Tools\capture.exe")]
    public void Read_ConcreteLocalToolPath_AcceptsAndCanonicalizesNeighbors_INV_B17_Issue64410334(
        string configuredPath,
        string expectedPath)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ToolPath] =
            configuredPath;
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.AreEqual(
            expectedPath,
            configuration.Capture?.ToolPath.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public void Read_LinuxPaths_AcceptsAbsoluteRootAndExtensionlessTool_CPL06()
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ArtifactRoot] =
            "/var/tmp/../rdma-evidence/";
        values[DiagnosticsConfigurationPropertyNames.ToolPath] =
            "/usr/sbin/tcpdump";
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt,
                runtimePlatform: DiagnosticsRuntimePlatform.Linux);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.AreEqual(
            "/var/rdma-evidence",
            configuration.ArtifactRoot?.Value);
        Assert.AreEqual(
            "/usr/sbin/tcpdump",
            configuration.Capture?.ToolPath.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [DataTestMethod]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        "relative/evidence")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        "//server/share/evidence")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        "/../../escape")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        "/var//evidence")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"C:\evidence")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        "/")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        "/usr/bin/")]
    public void Read_LinuxPath_RejectsInvalidAbsolutePath_CPL06(
        string propertyName,
        string configuredPath)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ArtifactRoot] =
            "/var/rdma-evidence";
        values[propertyName] = configuredPath;
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt,
                runtimePlatform: DiagnosticsRuntimePlatform.Linux);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        CollectionAssert.AreEqual(
            new[] { DiagnosticsConfigurationErrorCodes.InvalidValue },
            errors.Chronology.Select(error => error.Code).ToArray());
    }

    [TestMethod]
    public void Read_LinuxRoot_AcceptsLinuxSpecificFilenameComponents_CPL06()
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ArtifactRoot] =
            "/var/CON:trace.";
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt,
                runtimePlatform: DiagnosticsRuntimePlatform.Linux);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Enabled,
            configuration.State);
        Assert.AreEqual(
            "/var/CON:trace.",
            configuration.ArtifactRoot?.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [DataTestMethod]
    [DataRow("/var/rdma-evidence")]
    [DataRow(@"\var\rdma-evidence")]
    public void Read_WindowsRuntime_RejectsLinuxPathSyntax_CPL06(
        string configuredPath)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ArtifactRoot] =
            configuredPath;
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt,
                runtimePlatform: DiagnosticsRuntimePlatform.Windows);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code ==
                    DiagnosticsConfigurationErrorCodes.InvalidValue));
    }

    [TestMethod]
    public void Read_WindowsRuntime_RejectsExtensionlessToolPath_CPL06()
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ToolPath] =
            @"C:\Tools\tcpdump";
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt,
                runtimePlatform: DiagnosticsRuntimePlatform.Windows);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code ==
                    DiagnosticsConfigurationErrorCodes.InvalidValue));
    }

    [DataTestMethod]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, false)]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, true)]
    public void Read_ConcreteLocalPath_RejectsOverlongComponent_INV_B17_Issue64410334(
        string propertyName,
        bool executable)
    {
        string component = new('a', executable ? 252 : 256);
        if (executable)
        {
            component += ".exe";
        }

        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[propertyName] = @"C:\Evidence\" + component;
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code ==
                    DiagnosticsConfigurationErrorCodes.InvalidValue));
    }

    [DataTestMethod]
    [DataRow(DiagnosticsConfigurationPropertyNames.Enabled, "sometimes", DiagnosticsConfigurationErrorCodes.InvalidValue)]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, @"relative\evidence", DiagnosticsConfigurationErrorCodes.InvalidValue)]
    [DataRow(DiagnosticsConfigurationPropertyNames.StartTimeout, "5", DiagnosticsConfigurationErrorCodes.InvalidValue)]
    [DataRow(DiagnosticsConfigurationPropertyNames.StopTimeout, "00:00:00", DiagnosticsConfigurationErrorCodes.InvalidValue)]
    [DataRow(DiagnosticsConfigurationPropertyNames.MaxDuration, "-00:00:01", DiagnosticsConfigurationErrorCodes.InvalidValue)]
    [DataRow(DiagnosticsConfigurationPropertyNames.MaxBytes, "0", DiagnosticsConfigurationErrorCodes.InvalidValue)]
    [DataRow(DiagnosticsConfigurationPropertyNames.Targets, "10.20.30.40;;Adapter-B", DiagnosticsConfigurationErrorCodes.InvalidValue)]
    [DataRow(DiagnosticsConfigurationPropertyNames.TrafficScope, "Everything", DiagnosticsConfigurationErrorCodes.UnsupportedValue)]
    [DataRow(DiagnosticsConfigurationPropertyNames.Format, "ConvertedPcap", DiagnosticsConfigurationErrorCodes.UnsupportedValue)]
    [DataRow(DiagnosticsConfigurationPropertyNames.Retention, "DeleteSuccesses", DiagnosticsConfigurationErrorCodes.UnsupportedValue)]
    [DataRow(DiagnosticsConfigurationPropertyNames.NativeLogsEnabled, "yes", DiagnosticsConfigurationErrorCodes.InvalidValue)]
    public void Read_InvalidCanonicalValue_ReturnsInvalidAndRecordsClassifiedCaptureError_Issue64410334(
        string propertyName,
        string invalidValue,
        string expectedCode)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[propertyName] = invalidValue;
        var source = new TestEffectiveConfigurationSource(values);
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(source, errors, OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.AreEqual(
            propertyName != DiagnosticsConfigurationPropertyNames.Enabled,
            configuration.Enabled);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Category == DiagnosticErrorCategory.Capture &&
                    error.Code == expectedCode));
        Assert.IsFalse(
            errors.Chronology.Any(
                error => error.Message.Contains(invalidValue, StringComparison.Ordinal)),
            "Configuration errors must not echo potentially sensitive values.");
    }

    [TestMethod]
    public void Read_UnknownProvider_ReturnsInvalidAndRecordsUnsupportedProvider_Issue64410334()
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.Provider] = "UnregisteredProvider";
        var source = new TestEffectiveConfigurationSource(values);
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                source,
                errors,
                OccurredAt,
                new DiagnosticsConfigurationPolicy(new[] { "Dumpcap" }));

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code == DiagnosticsConfigurationErrorCodes.ProviderUnsupported));
    }

    [TestMethod]
    public void Read_ToolPathWithRelativeSegments_ReturnsCanonicalAbsolutePath_Issue64410334()
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ToolPath] =
            @"C:\Capture\bin\..\capture.exe";
        var source = new TestEffectiveConfigurationSource(values);

        DiagnosticsConfiguration configuration =
            Read(
                source,
                new DiagnosticErrorLedger(),
                OccurredAt);

        Assert.AreEqual(
            @"C:\Capture\capture.exe",
            configuration.Capture?.ToolPath.Value);
    }

    [TestMethod]
    public void Read_OverlongToolPath_ReturnsInvalidWithoutThrowing_Issue64410334()
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ToolPath] =
            @"C:\" + new string('a', 32768) + ".exe";
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code == DiagnosticsConfigurationErrorCodes.InvalidValue));
    }

    [TestMethod]
    public void Read_NulToolPath_ReturnsInvalidWithoutThrowing_Issue64410334()
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[DiagnosticsConfigurationPropertyNames.ToolPath] =
            "C:\\Capture\\capture\0.exe";
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code == DiagnosticsConfigurationErrorCodes.InvalidValue));
    }

    [DataTestMethod]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, @"\\server\share\evidence")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, "//server/share/evidence")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, @"\/server\share\evidence")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, @"/\server/share/evidence")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, @"\\?\C:\evidence")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, @"\\.\C:\evidence")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, @"\??\C:\evidence")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ArtifactRoot,
        @"\\?\Volume{11111111-1111-1111-1111-111111111111}\evidence")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, @"C:evidence")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, @"\evidence")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ArtifactRoot, @"relative\evidence")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"\\server\share\capture.exe")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, "//server/share/capture.exe")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"\/server\share\capture.exe")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"/\server/share/capture.exe")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"\\?\C:\capture.exe")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"\\.\C:\capture.exe")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"\??\C:\capture.exe")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"\\?\Volume{11111111-1111-1111-1111-111111111111}\capture.exe")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"C:capture.exe")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"\capture.exe")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"relative\capture.exe")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"C:\")]
    [DataRow(DiagnosticsConfigurationPropertyNames.ToolPath, @"C:\Tools\")]
    [DataRow(
        DiagnosticsConfigurationPropertyNames.ToolPath,
        @"C:\Tools\capture.exe\")]
    public void Read_NonLocalDrivePath_ReturnsInvalidWithoutThrowing_Issue64410334(
        string propertyName,
        string nonLocalPath)
    {
        Dictionary<string, string?> values =
            CreateValidValues(includeExplicitSelections: false);
        values[propertyName] = nonLocalPath;
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(
                new TestEffectiveConfigurationSource(values),
                errors,
                OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code == DiagnosticsConfigurationErrorCodes.InvalidValue));
        Assert.IsFalse(
            errors.Chronology.Any(
                error => error.Message.Contains(nonLocalPath, StringComparison.Ordinal)));
    }

    [TestMethod]
    public void Read_MissingRequiredEnabledValues_ReturnsInvalidWithOneErrorPerProperty_Issue64410334()
    {
        var source = new TestEffectiveConfigurationSource(
            new Dictionary<string, string?>
            {
                [DiagnosticsConfigurationPropertyNames.Enabled] = "true",
                ["SutPassword"] = "must-not-be-read",
            });
        var errors = new DiagnosticErrorLedger();

        DiagnosticsConfiguration configuration =
            Read(source, errors, OccurredAt);

        Assert.AreEqual(
            DiagnosticsConfigurationState.Invalid,
            configuration.State);
        CollectionAssert.AreEquivalent(
            new[]
            {
                DiagnosticsConfigurationPropertyNames.ArtifactRoot,
                DiagnosticsConfigurationPropertyNames.StartTimeout,
                DiagnosticsConfigurationPropertyNames.StopTimeout,
                DiagnosticsConfigurationPropertyNames.MaxDuration,
                DiagnosticsConfigurationPropertyNames.MaxBytes,
                SmbdDiagnosticsConfigurationProperties.ClientRNicIp,
            },
            errors.Chronology
                .Where(error => error.Code == DiagnosticsConfigurationErrorCodes.MissingValue)
                .Select(error => error.Message)
                .Select(message => ExtractQuotedProperty(message))
                .ToArray());
        CollectionAssert.DoesNotContain(
            source.RequestedProperties,
            "SutPassword");
    }

    internal static Dictionary<string, string?> CreateMalformedDisabledValues(
        string? enabled)
    {
        return new Dictionary<string, string?>
        {
            [DiagnosticsConfigurationPropertyNames.Enabled] = enabled,
            [DiagnosticsConfigurationPropertyNames.ArtifactRoot] =
                "relative-artifacts",
            [DiagnosticsConfigurationPropertyNames.Provider] =
                "invalid-provider",
            [DiagnosticsConfigurationPropertyNames.ToolPath] =
                "relative-tool.exe",
            [DiagnosticsConfigurationPropertyNames.Targets] = " ; ",
            [DiagnosticsConfigurationPropertyNames.TrafficScope] =
                "invalid-scope",
            [DiagnosticsConfigurationPropertyNames.StartTimeout] =
                "not-a-duration",
            [DiagnosticsConfigurationPropertyNames.StopTimeout] =
                "not-a-duration",
            [DiagnosticsConfigurationPropertyNames.MaxDuration] =
                "not-a-duration",
            [DiagnosticsConfigurationPropertyNames.MaxBytes] =
                "not-a-number",
            [DiagnosticsConfigurationPropertyNames.Format] = "invalid-format",
            [DiagnosticsConfigurationPropertyNames.NativeLogsEnabled] =
                "not-a-boolean",
            [DiagnosticsConfigurationPropertyNames.Retention] =
                "invalid-retention",
            [SmbdDiagnosticsConfigurationProperties.ClientRNicIp] =
                "not-an-ip-address",
            ["SutPassword"] = "must-not-be-read",
        };
    }

    internal static Dictionary<string, string?> CreateValidValues(
        bool includeExplicitSelections)
    {
        var values = new Dictionary<string, string?>
        {
            [DiagnosticsConfigurationPropertyNames.Enabled] = "true",
            [DiagnosticsConfigurationPropertyNames.ArtifactRoot] = @"C:\rdma-evidence",
            [DiagnosticsConfigurationPropertyNames.StartTimeout] = "00:00:05",
            [DiagnosticsConfigurationPropertyNames.StopTimeout] = "00:00:10",
            [DiagnosticsConfigurationPropertyNames.MaxDuration] = "00:02:00",
            [DiagnosticsConfigurationPropertyNames.MaxBytes] = "1048576",
            [SmbdDiagnosticsConfigurationProperties.ClientRNicIp] = "10.20.30.40",
            ["SutPassword"] = "must-not-be-read",
        };

        if (includeExplicitSelections)
        {
            values[DiagnosticsConfigurationPropertyNames.Provider] = " dumpCAP ";
            values[DiagnosticsConfigurationPropertyNames.Targets] =
                " 10.20.30.40 ; Adapter-B ";
            values[DiagnosticsConfigurationPropertyNames.TrafficScope] = " broader ";
            values[DiagnosticsConfigurationPropertyNames.NativeLogsEnabled] = " true ";
        }

        return values;
    }

    private static DiagnosticsConfiguration Read(
        IEffectiveConfigurationSource source,
        DiagnosticErrorLedger errors,
        DateTimeOffset occurredAt,
        DiagnosticsConfigurationPolicy? policy = null,
        DiagnosticsRuntimePlatform? runtimePlatform = null)
    {
        if (runtimePlatform.HasValue)
        {
            return DiagnosticsConfigurationReader.Read(
                source,
                errors,
                occurredAt,
                SmbdDiagnosticsConfigurationProperties.PropertyMap,
                policy,
                runtimePlatform.Value);
        }

        return DiagnosticsConfigurationReader.Read(
            source,
            errors,
            occurredAt,
            SmbdDiagnosticsConfigurationProperties.PropertyMap,
            policy);
    }

    private static string ExtractQuotedProperty(string message)
    {
        int start = message.IndexOf('\'') + 1;
        int end = message.IndexOf('\'', start);
        return message[start..end];
    }
}
