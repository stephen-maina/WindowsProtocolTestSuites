// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Configuration;

[TestClass]
public sealed class CaptureTargetResolverTests
{
    private const string SecretSentinel = "must-not-be-read";

    private static readonly DateTimeOffset OccurredAt =
        DateTimeOffset.Parse("2026-10-02T16:00:00Z");

    [TestMethod]
    public void Resolve_DisabledConfiguration_DoesNotEnumerateAdapters_Issue64410334()
    {
        var source = new TestEffectiveConfigurationSource(
            new Dictionary<string, string?>());
        DiagnosticsConfiguration configuration =
            DiagnosticsConfigurationReader.Read(
                source,
                new DiagnosticErrorLedger(),
                OccurredAt);
        bool enumerated = false;

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                enumerated = true;
                return Array.Empty<CaptureAdapterObservation>();
            },
            new DiagnosticErrorLedger(),
            OccurredAt);

        Assert.IsFalse(enumerated);
        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
    }

    [TestMethod]
    public void Resolve_InferredClientIp_ReturnsObservedStableAdapterIdentity_Issue64410334()
    {
        DiagnosticsConfiguration configuration = CreateConfiguration();
        var errors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000001}",
                interfaceName: "RDMA-A",
                providerSelector: "4",
                addresses: new[] { "10.20.30.40", "fe80::1" }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(1, resolution.Targets.Count);
        ResolvedCaptureTarget target = resolution.Targets.Single();
        Assert.AreEqual(
            ConfigurationProvenance.Inferred,
            target.RequestedSelector.Provenance);
        Assert.AreEqual(
            "{AAAA0000-0000-0000-0000-000000000001}",
            target.StableIdentifier.Value);
        Assert.AreEqual(
            ConfigurationProvenance.Observed,
            target.StableIdentifier.Provenance);
        Assert.AreEqual("RDMA-A", target.InterfaceName.Value);
        Assert.AreEqual("4", target.ProviderSelector.Value);
        Assert.AreEqual("mlx5.sys 25.1.0", target.DriverIdentity.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [DataTestMethod]
    [DataRow("10.20.30.99", DiagnosticsConfigurationErrorCodes.TargetNotFound)]
    [DataRow("Disconnected-RDMA", DiagnosticsConfigurationErrorCodes.TargetDisconnected)]
    public void Resolve_UnknownOrDisconnectedTarget_FailsExplicitly_Issue64410334(
        string target,
        string expectedCode)
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: target);
        var errors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000001}",
                interfaceName: "Disconnected-RDMA",
                providerSelector: "4",
                addresses: new[] { "10.20.30.40" },
                isConnected: false),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        Assert.IsFalse(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
        Assert.IsTrue(
            errors.Chronology.Any(error => error.Code == expectedCode));
        Assert.IsFalse(
            errors.Chronology.Any(
                error => error.Message.Contains(target, StringComparison.Ordinal)),
            "Target resolution errors must not echo potentially sensitive selectors.");
    }

    [TestMethod]
    public void Resolve_AmbiguousAddress_FailsRatherThanChoosingFirstAdapter_Issue64410334()
    {
        DiagnosticsConfiguration configuration = CreateConfiguration();
        var errors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000001}",
                interfaceName: "RDMA-A",
                providerSelector: "4",
                addresses: new[] { "10.20.30.40" }),
            CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000002}",
                interfaceName: "RDMA-B",
                providerSelector: "7",
                addresses: new[] { "10.20.30.40" }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations.Reverse().ToArray(),
            errors,
            OccurredAt);

        Assert.IsFalse(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code == DiagnosticsConfigurationErrorCodes.TargetAmbiguous));
    }

    [DataTestMethod]
    [DataRow("10.20.30.40")]
    [DataRow("{AAAA0000-0000-0000-0000-000000000001}")]
    [DataRow("RDMA-A")]
    public void Resolve_UniqueAdapterWithDuplicatedProviderSelector_FailsAmbiguous_Issue64410334(
        string selector)
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: selector);
        var errors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000001}",
                interfaceName: "RDMA-A",
                providerSelector: "4",
                addresses: new[] { "10.20.30.40" }),
            CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000002}",
                interfaceName: "RDMA-B",
                providerSelector: "4",
                addresses: new[] { "10.20.30.41" }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        AssertResolutionFailure(
            resolution,
            errors,
            DiagnosticsConfigurationErrorCodes.TargetAmbiguous,
            selector,
            SecretSentinel);
    }

    [TestMethod]
    public void Resolve_DuplicateObservedStableIdentity_FailsEvenWhenNameMatchIsUnique_Issue64410334()
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: "RDMA-A");
        var errors = new DiagnosticErrorLedger();
        const string DuplicateStableId =
            "{AAAA0000-0000-0000-0000-000000000001}";
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: DuplicateStableId,
                interfaceName: "RDMA-A",
                providerSelector: "4",
                addresses: new[] { "10.20.30.40" }),
            CreateObservation(
                stableIdentifier: DuplicateStableId,
                interfaceName: "RDMA-B",
                providerSelector: "7",
                addresses: new[] { "10.20.30.41" }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        Assert.IsFalse(resolution.IsSuccessful);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code == DiagnosticsConfigurationErrorCodes.TargetAmbiguous));
    }

    [TestMethod]
    public void Resolve_NumericProviderSelector_RemainsExactAndDoesNotBecomeIpv4_Issue64410334()
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: "4");
        var errors = new DiagnosticErrorLedger();
        const string ExpectedStableIdentifier =
            "{AAAA0000-0000-0000-0000-000000000004}";
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: ExpectedStableIdentifier,
                interfaceName: "RDMA-Index-4",
                providerSelector: "4",
                addresses: new[] { "10.20.30.40" }),
            CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000099}",
                interfaceName: "IPv4-Lookalike",
                providerSelector: "99",
                addresses: new[] { "0.0.0.4" }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(1, resolution.Targets.Count);
        Assert.AreEqual(
            "4",
            resolution.Targets.Single().RequestedSelector.Value);
        Assert.AreEqual(
            ExpectedStableIdentifier,
            resolution.Targets.Single().StableIdentifier.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public void Resolve_LegacyAbbreviatedIpv4_IsExactIdentifierNotAddress_Issue64410334()
    {
        const string Selector = "10.1";
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: Selector);
        var errors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000010}",
                interfaceName: "RDMA-Legacy-Lookalike",
                providerSelector: "10",
                addresses: new[] { "10.0.0.1" }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        AssertResolutionFailure(
            resolution,
            errors,
            DiagnosticsConfigurationErrorCodes.TargetNotFound,
            Selector,
            SecretSentinel);
    }

    [TestMethod]
    public void Resolve_LeadingZeroIpv4Shape_PreservesExactIdentity_INV_B21_Issue64410334()
    {
        const string Selector = "192.168.001.010";
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: Selector);
        var errors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: Selector,
                interfaceName: "RDMA-Leading-Zero-Identifier",
                providerSelector: "leading-zero-provider",
                addresses: new[] { "192.168.1.10" }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(1, resolution.Targets.Count);
        Assert.AreEqual(
            Selector,
            resolution.Targets.Single().RequestedSelector.Value);
        Assert.AreEqual(
            Selector,
            resolution.Targets.Single().StableIdentifier.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [DataTestMethod]
    [DataRow("StableIdentifier")]
    [DataRow("InterfaceName")]
    [DataRow("ProviderSelector")]
    public void Resolve_ExactIdentifierWinsGloballyOverAddressMatch_INV_B15_Issue64410334(
        string exactField)
    {
        const string Selector = "10.20.30.40";
        const string ExpectedStableIdentifier = "exact-observation";
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: Selector);
        var errors = new DiagnosticErrorLedger();
        string stableIdentifier =
            exactField == "StableIdentifier"
                ? Selector
                : ExpectedStableIdentifier;
        string interfaceName =
            exactField == "InterfaceName"
                ? Selector
                : "RDMA-Exact";
        string providerSelector =
            exactField == "ProviderSelector"
                ? Selector
                : "exact-provider";
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier,
                interfaceName,
                providerSelector,
                addresses: new[] { "192.0.2.10" }),
            CreateObservation(
                stableIdentifier: "address-observation",
                interfaceName: "RDMA-Address",
                providerSelector: "address-provider",
                addresses: new[] { Selector }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(1, resolution.Targets.Count);
        Assert.AreEqual(
            stableIdentifier,
            resolution.Targets.Single().StableIdentifier.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public void Resolve_Ipv6ShapedExactIdentifierPreservesSourceTokenBeforeAddressFallback_INV_B15_Issue64410334()
    {
        const string ExactToken = "2001:0db8:0:0:0:0:0:1";
        const string CanonicalAddress = "2001:db8::1";
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: ExactToken);
        var errors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: ExactToken,
                interfaceName: "RDMA-Exact-IPv6-Token",
                providerSelector: "exact-ipv6-token",
                addresses: new[] { "192.0.2.10" }),
            CreateObservation(
                stableIdentifier: "address-observation",
                interfaceName: "RDMA-IPv6-Address",
                providerSelector: "address-ipv6",
                addresses: new[] { CanonicalAddress }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(
            ExactToken,
            resolution.Targets.Single().StableIdentifier.Value);
        Assert.AreEqual(
            CanonicalAddress,
            resolution.Targets.Single().RequestedSelector.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [DataTestMethod]
    [DataRow("{AAAA0000-0000-0000-0000-000000000001}")]
    [DataRow("RDMA-A")]
    public void Resolve_UniqueExactIdentifierSelector_RemainsValid_Issue64410334(
        string selector)
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: selector);
        var errors = new DiagnosticErrorLedger();
        const string ExpectedStableIdentifier =
            "{AAAA0000-0000-0000-0000-000000000001}";
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: ExpectedStableIdentifier,
                interfaceName: "RDMA-A",
                providerSelector: "4",
                addresses: new[] { "10.20.30.40" }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(
            ExpectedStableIdentifier,
            resolution.Targets.Single().StableIdentifier.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public void Observation_NonIpAddress_RejectsInvalidObservedInventory_Issue64410334()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000001}",
                interfaceName: "RDMA-A",
                providerSelector: "4",
                addresses: new[] { "not-an-ip-address" }));
    }

    [DataTestMethod]
    [DataRow("fe80::1%12")]
    [DataRow("[fe80::1]:443")]
    public void Observation_DecoratedIpv6_RejectsInvalidObservedInventoryWithoutLeak_INV_B19_Issue64410334(
        string observedAddress)
    {
        ArgumentException exception =
            Assert.ThrowsExactly<ArgumentException>(
                () => CreateObservation(
                    stableIdentifier:
                        "{AAAA0000-0000-0000-0000-000000000001}",
                    interfaceName: "RDMA-A",
                    providerSelector: "4",
                    addresses: new[] { observedAddress }));

        Assert.IsFalse(
            exception.Message.Contains(
                observedAddress,
                StringComparison.Ordinal));
    }

    [DataTestMethod]
    [DataRow("10.1")]
    [DataRow("4")]
    [DataRow("192.168.001.010")]
    public void Observation_PermissiveIpv4Shape_RejectsInvalidObservedInventory_INV_B15_Issue64410334(
        string observedAddress)
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000001}",
                interfaceName: "RDMA-A",
                providerSelector: "4",
                addresses: new[] { observedAddress }));
    }

    [DataTestMethod]
    [DataRow("StableIdentifier")]
    [DataRow("InterfaceName")]
    [DataRow("ProviderSelector")]
    [DataRow("PhysicalAdapterIdentifier")]
    [DataRow("DriverIdentity")]
    [DataRow("Address")]
    public void Observation_ControlContainingIdentityOrAddress_RejectsWithoutLeak_INV_B20_Issue64410334(
        string invalidField)
    {
        string invalidValue =
            invalidField == "Address"
                ? "192.0.2.30\u0001"
                : "observed\u0001identity";

        ArgumentException exception =
            Assert.ThrowsExactly<ArgumentException>(
                () => CreateObservationWithField(
                    invalidField,
                    invalidValue));

        Assert.IsFalse(
            exception.Message.Contains(
                invalidValue,
                StringComparison.Ordinal));
    }

    [DataTestMethod]
    [DataRow("StableIdentifier", "Leading")]
    [DataRow("StableIdentifier", "Trailing")]
    [DataRow("StableIdentifier", "WhitespaceOnly")]
    [DataRow("StableIdentifier", "Empty")]
    [DataRow("InterfaceName", "Leading")]
    [DataRow("InterfaceName", "Trailing")]
    [DataRow("InterfaceName", "WhitespaceOnly")]
    [DataRow("InterfaceName", "Empty")]
    [DataRow("ProviderSelector", "Leading")]
    [DataRow("ProviderSelector", "Trailing")]
    [DataRow("ProviderSelector", "WhitespaceOnly")]
    [DataRow("ProviderSelector", "Empty")]
    [DataRow("PhysicalAdapterIdentifier", "Leading")]
    [DataRow("PhysicalAdapterIdentifier", "Trailing")]
    [DataRow("PhysicalAdapterIdentifier", "WhitespaceOnly")]
    [DataRow("PhysicalAdapterIdentifier", "Empty")]
    [DataRow("DriverIdentity", "Leading")]
    [DataRow("DriverIdentity", "Trailing")]
    [DataRow("DriverIdentity", "WhitespaceOnly")]
    [DataRow("DriverIdentity", "Empty")]
    [DataRow("Address", "Leading")]
    [DataRow("Address", "Trailing")]
    [DataRow("Address", "WhitespaceOnly")]
    [DataRow("Address", "Empty")]
    public void Observation_BoundaryWhitespaceOrWhitespaceOnlyIdentityOrAddress_RejectsWithoutLeak_INV_B20_Issue64410334(
        string invalidField,
        string invalidKind)
    {
        string validValue =
            invalidField == "Address"
                ? "192.0.2.30"
                : "observed-identity";
        string invalidValue = invalidKind switch
        {
            "Leading" => " " + validValue,
            "Trailing" => validValue + " ",
            "WhitespaceOnly" => "   ",
            _ => string.Empty,
        };

        ArgumentException exception =
            Assert.ThrowsExactly<ArgumentException>(
                () => CreateObservationWithField(
                    invalidField,
                    invalidValue));

        if (invalidValue.Length > 0)
        {
            Assert.IsFalse(
                exception.Message.Contains(
                    invalidValue,
                    StringComparison.Ordinal));
        }
    }

    [TestMethod]
    public void Observation_ValidExactIdentityText_IsPreserved_INV_B20_Issue64410334()
    {
        var observation = new CaptureAdapterObservation(
            stableIdentifier: "stable identity",
            interfaceName: "Ethernet 2",
            providerSelector: "provider selector",
            addresses: new[] { "192.0.2.30" },
            isConnected: true,
            physicalAdapterIdentifier: "PCI adapter identity",
            driverIdentity: "mlx5 driver 25.1.0");

        Assert.AreEqual("stable identity", observation.StableIdentifier);
        Assert.AreEqual("Ethernet 2", observation.InterfaceName);
        Assert.AreEqual("provider selector", observation.ProviderSelector);
        Assert.AreEqual(
            "PCI adapter identity",
            observation.PhysicalAdapterIdentifier);
        Assert.AreEqual("mlx5 driver 25.1.0", observation.DriverIdentity);
        CollectionAssert.AreEqual(
            new[] { "192.0.2.30" },
            observation.Addresses.ToArray());
    }

    [TestMethod]
    public void Observation_MissingOptionalPhysicalAdapterIdentifier_RemainsAccepted_INV_B20_Issue64410334()
    {
        var observation = new CaptureAdapterObservation(
            stableIdentifier: "stable-identifier",
            interfaceName: "RDMA-A",
            providerSelector: "4",
            addresses: new[] { "192.0.2.30" },
            isConnected: true,
            physicalAdapterIdentifier: null,
            driverIdentity: "mlx5.sys 25.1.0");

        Assert.IsNull(observation.PhysicalAdapterIdentifier);
    }

    [TestMethod]
    public void Resolve_InventoryProviderAndSourceAreMaterializedOnce_INV_B24_Issue64410334()
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: "RDMA-A");
        var errors = new DiagnosticErrorLedger();
        var observations =
            new CountingReadOnlyList<CaptureAdapterObservation>(
                new[]
                {
                    CreateObservation(
                        stableIdentifier:
                            "{AAAA0000-0000-0000-0000-000000000001}",
                        interfaceName: "RDMA-A",
                        providerSelector: "4",
                        addresses: new[] { "10.20.30.40" }),
                });
        int callbackCount = 0;

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                callbackCount++;
                return observations;
            },
            errors,
            OccurredAt);

        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(1, resolution.Targets.Count);
        Assert.AreEqual(1, callbackCount);
        Assert.AreEqual(1, observations.EnumerationCount);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public void Resolve_TwoSelectorsForSameAdapter_FailsDuplicateIdentity_Issue64410334()
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(
                explicitTargets:
                    "10.20.30.40;{AAAA0000-0000-0000-0000-000000000001}");
        var errors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000001}",
                interfaceName: "RDMA-A",
                providerSelector: "4",
                addresses: new[] { "10.20.30.40" }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        Assert.IsFalse(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code ==
                    DiagnosticsConfigurationErrorCodes.DuplicateTargetIdentity));
    }

    [TestMethod]
    public void Resolve_InventoryException_RecordsUnavailableWithoutEscaping_Issue64410334()
    {
        DiagnosticsConfiguration configuration = CreateConfiguration();
        var errors = new DiagnosticErrorLedger();
        int callbackCount = 0;
        const string ExceptionSecret =
            "inventory-callback-secret-must-not-leak";

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                callbackCount++;
                throw new CaptureAdapterInventoryException(
                    ExceptionSecret);
            },
            errors,
            OccurredAt);

        Assert.AreEqual(1, callbackCount);
        AssertResolutionFailure(
            resolution,
            errors,
            DiagnosticsConfigurationErrorCodes.AdapterInventoryUnavailable,
            ExceptionSecret,
            SecretSentinel);
    }

    [TestMethod]
    public void Resolve_InventoryMaterializationException_RecordsOneSafeUnavailableError_INV_B25_Issue64410334()
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: "RDMA-A;RDMA-B");
        var errors = new DiagnosticErrorLedger();
        const string ExceptionSecret =
            "inventory-enumeration-secret-must-not-leak";
        var observations =
            new ThrowingEnumerationReadOnlyList<CaptureAdapterObservation>(
                new[]
                {
                    CreateObservation(
                        stableIdentifier:
                            "{AAAA0000-0000-0000-0000-000000000001}",
                        interfaceName: "RDMA-A",
                        providerSelector: "4",
                        addresses: new[] { "10.20.30.40" }),
                },
                new CaptureAdapterInventoryException(ExceptionSecret));
        int callbackCount = 0;

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                callbackCount++;
                return observations;
            },
            errors,
            OccurredAt);

        Assert.AreEqual(1, callbackCount);
        Assert.AreEqual(1, observations.EnumerationCount);
        AssertResolutionFailure(
            resolution,
            errors,
            DiagnosticsConfigurationErrorCodes.AdapterInventoryUnavailable,
            ExceptionSecret,
            "RDMA-A",
            "RDMA-B",
            SecretSentinel);
    }

    [TestMethod]
    public void Resolve_NullInventoryObservation_RecordsOneDeterministicSafeUnavailableError_INV_B25_Issue64410334()
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: "RDMA-A;RDMA-B");
        var errors = new DiagnosticErrorLedger();
        var observations = new CaptureAdapterObservation[]
        {
            CreateObservation(
                stableIdentifier:
                    "{AAAA0000-0000-0000-0000-000000000001}",
                interfaceName: "RDMA-A",
                providerSelector: "4",
                addresses: new[] { "10.20.30.40" }),
            null!,
        };
        int callbackCount = 0;

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                callbackCount++;
                return observations;
            },
            errors,
            OccurredAt);

        Assert.AreEqual(1, callbackCount);
        AssertResolutionFailure(
            resolution,
            errors,
            DiagnosticsConfigurationErrorCodes.AdapterInventoryUnavailable,
            "RDMA-A",
            "RDMA-B",
            SecretSentinel);
        Assert.AreEqual(
            "The capture adapter inventory contained an invalid observation.",
            errors.Chronology.Single().Message);
    }

    [TestMethod]
    public void Resolve_UnexpectedInventoryMaterializationException_Propagates_INV_B25_Issue64410334()
    {
        DiagnosticsConfiguration configuration = CreateConfiguration();
        var errors = new DiagnosticErrorLedger();
        var expectedException = new InvalidOperationException(
            "Unexpected inventory enumeration defect.");
        var observations =
            new ThrowingEnumerationReadOnlyList<CaptureAdapterObservation>(
                new[]
                {
                    CreateObservation(
                        stableIdentifier:
                            "{AAAA0000-0000-0000-0000-000000000001}",
                        interfaceName: "RDMA-A",
                        providerSelector: "4",
                        addresses: new[] { "10.20.30.40" }),
                },
                expectedException);
        int callbackCount = 0;

        InvalidOperationException actualException =
            Assert.ThrowsExactly<InvalidOperationException>(
                () => CaptureTargetResolver.Resolve(
                    configuration,
                    () =>
                    {
                        callbackCount++;
                        return observations;
                    },
                    errors,
                    OccurredAt));

        Assert.AreSame(expectedException, actualException);
        Assert.AreEqual(1, callbackCount);
        Assert.AreEqual(1, observations.EnumerationCount);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public void Resolve_NullInventory_RecordsUnavailableWithoutEscaping_Issue64410334()
    {
        DiagnosticsConfiguration configuration = CreateConfiguration();
        var errors = new DiagnosticErrorLedger();
        int callbackCount = 0;

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                callbackCount++;
                return null!;
            },
            errors,
            OccurredAt);

        Assert.AreEqual(1, callbackCount);
        AssertResolutionFailure(
            resolution,
            errors,
            DiagnosticsConfigurationErrorCodes.AdapterInventoryUnavailable,
            SecretSentinel);
    }

    [TestMethod]
    public void Resolve_UnexpectedInventoryException_Propagates_Issue64410334()
    {
        DiagnosticsConfiguration configuration = CreateConfiguration();
        var errors = new DiagnosticErrorLedger();
        int callbackCount = 0;

        InvalidOperationException exception =
            Assert.ThrowsExactly<InvalidOperationException>(
                () => CaptureTargetResolver.Resolve(
                    configuration,
                    () =>
                    {
                        callbackCount++;
                        throw new InvalidOperationException(
                            "Unexpected inventory defect.");
                    },
                    errors,
                    OccurredAt));

        Assert.AreEqual(1, callbackCount);
        Assert.AreEqual(
            "Unexpected inventory defect.",
            exception.Message);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public void Resolve_MixedSuccessfulAndFailedTargets_EmitsNoPartialResult_Issue64410334()
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(explicitTargets: "RDMA-A;Missing-RDMA");
        var errors = new DiagnosticErrorLedger();
        var observations =
            new CountingReadOnlyList<CaptureAdapterObservation>(
                new[]
                {
                    CreateObservation(
                        stableIdentifier:
                            "{AAAA0000-0000-0000-0000-000000000001}",
                        interfaceName: "RDMA-A",
                        providerSelector: "4",
                        addresses: new[] { "10.20.30.40" }),
                });
        int callbackCount = 0;

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () =>
            {
                callbackCount++;
                return observations;
            },
            errors,
            OccurredAt);

        Assert.AreEqual(1, callbackCount);
        Assert.AreEqual(1, observations.EnumerationCount);
        AssertResolutionFailure(
            resolution,
            errors,
            DiagnosticsConfigurationErrorCodes.TargetNotFound,
            "RDMA-A",
            "Missing-RDMA",
            SecretSentinel);
    }

    [TestMethod]
    public void Resolve_Ipv6Selector_MatchesCanonicalObservedAddress_Issue64410334()
    {
        DiagnosticsConfiguration configuration =
            CreateConfiguration(
                explicitTargets: "2001:0db8:0:0:0:0:0:1");
        var errors = new DiagnosticErrorLedger();
        var observations = new[]
        {
            CreateObservation(
                stableIdentifier: "{AAAA0000-0000-0000-0000-000000000006}",
                interfaceName: "RDMA-IPv6",
                providerSelector: "6",
                addresses: new[] { "2001:db8::1" }),
        };

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => observations,
            errors,
            OccurredAt);

        Assert.IsTrue(resolution.IsSuccessful);
        Assert.AreEqual(
            "2001:db8::1",
            resolution.Targets.Single().RequestedSelector.Value);
        Assert.AreEqual(0, errors.Chronology.Count);
    }

    [TestMethod]
    public void Resolve_EmptyInventory_RecordsTargetNotFound_Issue64410334()
    {
        DiagnosticsConfiguration configuration = CreateConfiguration();
        var errors = new DiagnosticErrorLedger();

        CaptureTargetResolution resolution = CaptureTargetResolver.Resolve(
            configuration,
            () => Array.Empty<CaptureAdapterObservation>(),
            errors,
            OccurredAt);

        Assert.IsFalse(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
        Assert.IsTrue(
            errors.Chronology.Any(
                error =>
                    error.Code ==
                    DiagnosticsConfigurationErrorCodes.TargetNotFound));
    }

    private static DiagnosticsConfiguration CreateConfiguration(
        string? explicitTargets = null)
    {
        Dictionary<string, string?> values =
            DiagnosticsConfigurationReaderTests.CreateValidValues(
                includeExplicitSelections: false);
        if (explicitTargets is not null)
        {
            values[DiagnosticsConfigurationPropertyNames.Targets] =
                explicitTargets;
        }

        return DiagnosticsConfigurationReader.Read(
            new TestEffectiveConfigurationSource(values),
            new DiagnosticErrorLedger(),
            OccurredAt,
            SmbdDiagnosticsConfigurationProperties.PropertyMap);
    }

    private static CaptureAdapterObservation CreateObservation(
        string stableIdentifier,
        string interfaceName,
        string providerSelector,
        IReadOnlyList<string> addresses,
        bool isConnected = true)
    {
        return new CaptureAdapterObservation(
            stableIdentifier,
            interfaceName,
            providerSelector,
            addresses,
            isConnected,
            physicalAdapterIdentifier: "PCI\\VEN_15B3&DEV_101D",
            driverIdentity: "mlx5.sys 25.1.0");
    }

    private static CaptureAdapterObservation CreateObservationWithField(
        string field,
        string value)
    {
        return new CaptureAdapterObservation(
            stableIdentifier:
                field == "StableIdentifier"
                    ? value
                    : "stable-identifier",
            interfaceName:
                field == "InterfaceName"
                    ? value
                    : "RDMA-A",
            providerSelector:
                field == "ProviderSelector"
                    ? value
                    : "4",
            addresses:
                new[]
                {
                    field == "Address"
                        ? value
                        : "192.0.2.30",
                },
            isConnected: true,
            physicalAdapterIdentifier:
                field == "PhysicalAdapterIdentifier"
                    ? value
                    : "PCI\\VEN_15B3&DEV_101D",
            driverIdentity:
                field == "DriverIdentity"
                    ? value
                    : "mlx5.sys 25.1.0");
    }

    private sealed class CountingReadOnlyList<T> : IReadOnlyList<T>
    {
        private readonly IReadOnlyList<T> items;

        internal CountingReadOnlyList(IReadOnlyList<T> items)
        {
            this.items = items;
        }

        internal int EnumerationCount { get; private set; }

        public int Count => items.Count;

        public T this[int index] => items[index];

        public IEnumerator<T> GetEnumerator()
        {
            EnumerationCount++;
            return items.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }

    private sealed class ThrowingEnumerationReadOnlyList<T> : IReadOnlyList<T>
    {
        private readonly IReadOnlyList<T> prefix;
        private readonly Exception exception;

        internal ThrowingEnumerationReadOnlyList(
            IReadOnlyList<T> prefix,
            Exception exception)
        {
            this.prefix = prefix;
            this.exception = exception;
        }

        internal int EnumerationCount { get; private set; }

        public int Count => prefix.Count + 1;

        public T this[int index] =>
            index < prefix.Count
                ? prefix[index]
                : throw exception;

        public IEnumerator<T> GetEnumerator()
        {
            EnumerationCount++;
            return Enumerate().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        private IEnumerable<T> Enumerate()
        {
            foreach (T item in prefix)
            {
                yield return item;
            }

            throw exception;
        }
    }

    private static void AssertResolutionFailure(
        CaptureTargetResolution resolution,
        DiagnosticErrorLedger errors,
        string expectedCode,
        params string[] valuesThatMustNotLeak)
    {
        Assert.IsFalse(resolution.IsSuccessful);
        Assert.AreEqual(0, resolution.Targets.Count);
        CollectionAssert.AreEqual(
            new[] { expectedCode },
            errors.Chronology.Select(error => error.Code).ToArray());
        foreach (string value in valuesThatMustNotLeak)
        {
            Assert.IsFalse(
                errors.Chronology.Any(
                    error => error.Message.Contains(
                        value,
                        StringComparison.Ordinal)),
                $"Target resolution errors must not reveal '{value}'.");
        }
    }
}
