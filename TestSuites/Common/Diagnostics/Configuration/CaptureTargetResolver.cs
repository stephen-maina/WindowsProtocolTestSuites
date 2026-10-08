// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Microsoft.Protocols.TestSuites.Diagnostics.Errors;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Configuration;

public sealed class CaptureAdapterObservation
{
    public CaptureAdapterObservation(
        string stableIdentifier,
        string interfaceName,
        string providerSelector,
        IReadOnlyList<string> addresses,
        bool isConnected,
        string? physicalAdapterIdentifier,
        string driverIdentity)
    {
        StableIdentifier = RequireText(
            stableIdentifier,
            nameof(stableIdentifier));
        InterfaceName = RequireText(interfaceName, nameof(interfaceName));
        ProviderSelector = RequireText(
            providerSelector,
            nameof(providerSelector));
        ArgumentNullException.ThrowIfNull(addresses);
        Addresses = new ReadOnlyCollection<string>(
            addresses
                .Select(RequireAddress)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList());
        IsConnected = isConnected;
        PhysicalAdapterIdentifier = physicalAdapterIdentifier is null
            ? null
            : RequireText(
                physicalAdapterIdentifier,
                nameof(physicalAdapterIdentifier));
        DriverIdentity = RequireText(driverIdentity, nameof(driverIdentity));
    }

    public string StableIdentifier { get; }

    public string InterfaceName { get; }

    public string ProviderSelector { get; }

    public IReadOnlyList<string> Addresses { get; }

    public bool IsConnected { get; }

    public string? PhysicalAdapterIdentifier { get; }

    public string DriverIdentity { get; }

    private static string RequireAddress(string address)
    {
        string value = RequireText(address, nameof(address));
        if (!CaptureTargetResolver.TryCanonicalizeIpLiteral(
                value,
                out string canonicalAddress))
        {
            throw new ArgumentException(
                "An observed adapter address must be an IP address.",
                nameof(address));
        }

        return canonicalAddress;
    }

    private static string RequireText(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Any(char.IsControl) ||
            !string.Equals(value, value.Trim(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "A non-empty value is required.",
                parameterName);
        }

        return value;
    }
}

public sealed class ResolvedCaptureTarget
{
    internal ResolvedCaptureTarget(
        ProvenancedValue<string> requestedSelector,
        CaptureAdapterObservation observation)
    {
        RequestedSelector = requestedSelector;
        StableIdentifier = Observed(observation.StableIdentifier);
        InterfaceName = Observed(observation.InterfaceName);
        ProviderSelector = Observed(observation.ProviderSelector);
        PhysicalAdapterIdentifier =
            new ProvenancedValue<string?>(
                observation.PhysicalAdapterIdentifier,
                ConfigurationProvenance.Observed);
        DriverIdentity = Observed(observation.DriverIdentity);
    }

    public ProvenancedValue<string> RequestedSelector { get; }

    public ProvenancedValue<string> StableIdentifier { get; }

    public ProvenancedValue<string> InterfaceName { get; }

    public ProvenancedValue<string> ProviderSelector { get; }

    public ProvenancedValue<string?> PhysicalAdapterIdentifier { get; }

    public ProvenancedValue<string> DriverIdentity { get; }

    private static ProvenancedValue<string> Observed(string value)
    {
        return new ProvenancedValue<string>(
            value,
            ConfigurationProvenance.Observed);
    }
}

public sealed class CaptureTargetResolution
{
    internal CaptureTargetResolution(
        bool isSuccessful,
        IReadOnlyList<ResolvedCaptureTarget> targets)
    {
        IsSuccessful = isSuccessful;
        Targets = new ReadOnlyCollection<ResolvedCaptureTarget>(
            new List<ResolvedCaptureTarget>(targets));
    }

    public bool IsSuccessful { get; }

    public IReadOnlyList<ResolvedCaptureTarget> Targets { get; }
}

public sealed class CaptureAdapterInventoryException : Exception
{
    public CaptureAdapterInventoryException(string message)
        : base(message)
    {
    }

    public CaptureAdapterInventoryException(
        string message,
        Exception innerException)
        : base(message, innerException)
    {
    }
}

public static class CaptureTargetResolver
{
    public static CaptureTargetResolution Resolve(
        DiagnosticsConfiguration configuration,
        Func<IReadOnlyList<CaptureAdapterObservation>> observeAdapters,
        DiagnosticErrorLedger errors,
        DateTimeOffset occurredAt)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(observeAdapters);
        ArgumentNullException.ThrowIfNull(errors);

        if (configuration.State == DiagnosticsConfigurationState.Disabled)
        {
            return new CaptureTargetResolution(
                isSuccessful: true,
                Array.Empty<ResolvedCaptureTarget>());
        }

        if (configuration.State != DiagnosticsConfigurationState.Enabled ||
            configuration.Capture is null)
        {
            return new CaptureTargetResolution(
                isSuccessful: false,
                Array.Empty<ResolvedCaptureTarget>());
        }

        CaptureAdapterObservation[] observationSnapshot;
        try
        {
            IReadOnlyList<CaptureAdapterObservation>? observations =
                observeAdapters();
            if (observations is null)
            {
                errors.Record(
                    DiagnosticErrorCategory.Capture,
                    DiagnosticsConfigurationErrorCodes.AdapterInventoryUnavailable,
                    "The capture adapter observation source returned no inventory.",
                    occurredAt);
                return new CaptureTargetResolution(
                    isSuccessful: false,
                    Array.Empty<ResolvedCaptureTarget>());
            }

            observationSnapshot = observations.ToArray();
        }
        catch (CaptureAdapterInventoryException)
        {
            errors.Record(
                DiagnosticErrorCategory.Capture,
                DiagnosticsConfigurationErrorCodes.AdapterInventoryUnavailable,
                "The capture adapter inventory could not be observed.",
                occurredAt);
            return new CaptureTargetResolution(
                isSuccessful: false,
                Array.Empty<ResolvedCaptureTarget>());
        }

        if (observationSnapshot.Any(
                static observation => observation is null))
        {
            errors.Record(
                DiagnosticErrorCategory.Capture,
                DiagnosticsConfigurationErrorCodes.AdapterInventoryUnavailable,
                "The capture adapter inventory contained an invalid observation.",
                occurredAt);
            return new CaptureTargetResolution(
                isSuccessful: false,
                Array.Empty<ResolvedCaptureTarget>());
        }
        var resolved = new List<ResolvedCaptureTarget>();
        for (int index = 0;
             index < configuration.Capture.TargetSelectors.Count;
             index++)
        {
            CaptureTargetSelector target =
                configuration.Capture.TargetSelectors[index];
            CaptureAdapterObservation[] exactMatches = observationSnapshot
                .Where(
                    observation => MatchesExact(
                        target.ExactToken,
                        observation))
                .OrderBy(
                    observation => observation.StableIdentifier,
                    StringComparer.OrdinalIgnoreCase)
                .ToArray();
            CaptureAdapterObservation[] matches =
                exactMatches.Length > 0
                    ? exactMatches
                    : target.CanonicalAddress is null
                        ? Array.Empty<CaptureAdapterObservation>()
                        : observationSnapshot
                            .Where(
                                observation =>
                                    observation.Addresses.Contains(
                                        target.CanonicalAddress,
                                        StringComparer.OrdinalIgnoreCase))
                            .OrderBy(
                                observation =>
                                    observation.StableIdentifier,
                                StringComparer.OrdinalIgnoreCase)
                            .ToArray();
            if (matches.Length == 0)
            {
                RecordTargetError(
                    errors,
                    DiagnosticsConfigurationErrorCodes.TargetNotFound,
                    index,
                    occurredAt);
                continue;
            }

            if (matches.Length != 1)
            {
                RecordTargetError(
                    errors,
                    DiagnosticsConfigurationErrorCodes.TargetAmbiguous,
                    index,
                    occurredAt);
                continue;
            }

            CaptureAdapterObservation match = matches[0];
            if (observationSnapshot.Count(
                    observation => string.Equals(
                        observation.StableIdentifier,
                        match.StableIdentifier,
                        StringComparison.OrdinalIgnoreCase)) != 1)
            {
                RecordTargetError(
                    errors,
                    DiagnosticsConfigurationErrorCodes.TargetAmbiguous,
                    index,
                    occurredAt);
                continue;
            }

            if (observationSnapshot.Count(
                    observation => string.Equals(
                        observation.ProviderSelector,
                        match.ProviderSelector,
                        StringComparison.OrdinalIgnoreCase)) != 1)
            {
                RecordTargetError(
                    errors,
                    DiagnosticsConfigurationErrorCodes.TargetAmbiguous,
                    index,
                    occurredAt);
                continue;
            }

            if (!match.IsConnected)
            {
                RecordTargetError(
                    errors,
                    DiagnosticsConfigurationErrorCodes.TargetDisconnected,
                    index,
                    occurredAt);
                continue;
            }

            if (resolved.Any(
                    existing => string.Equals(
                        existing.StableIdentifier.Value,
                        match.StableIdentifier,
                        StringComparison.OrdinalIgnoreCase)))
            {
                RecordTargetError(
                    errors,
                    DiagnosticsConfigurationErrorCodes.DuplicateTargetIdentity,
                    index,
                    occurredAt);
                continue;
            }

            resolved.Add(
                new ResolvedCaptureTarget(
                    target.EffectiveValue,
                    match));
        }

        bool succeeded =
            resolved.Count ==
            configuration.Capture.TargetSelectors.Count;
        return new CaptureTargetResolution(
            succeeded,
            succeeded
                ? resolved
                : Array.Empty<ResolvedCaptureTarget>());
    }

    private static bool MatchesExact(
        string selector,
        CaptureAdapterObservation observation)
    {
        return string.Equals(
                selector,
                observation.StableIdentifier,
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(
                selector,
                observation.InterfaceName,
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(
                selector,
                observation.ProviderSelector,
                StringComparison.OrdinalIgnoreCase);
    }

    internal static bool TryCreateSelector(
        string selector,
        ConfigurationProvenance provenance,
        out CaptureTargetSelector target)
    {
        if (selector.Any(char.IsControl))
        {
            target = null!;
            return false;
        }

        string trimmedSelector = selector.Trim();
        if (trimmedSelector.Length == 0)
        {
            target = null!;
            return false;
        }

        if (IsDecoratedIpv6AddressCandidate(trimmedSelector))
        {
            target = null!;
            return false;
        }

        if (TryCanonicalizeIpLiteral(
                trimmedSelector,
                out string canonicalIpLiteral))
        {
            target = new CaptureTargetSelector(
                trimmedSelector,
                canonicalIpLiteral,
                provenance);
            return true;
        }

        target = new CaptureTargetSelector(
            trimmedSelector,
            canonicalAddress: null,
            provenance);
        return true;
    }

    internal static bool TryCanonicalizeIpLiteral(
        string selector,
        out string canonicalSelector)
    {
        if (selector.Contains(':'))
        {
            if (selector.Any(
                    character =>
                        !char.IsAsciiHexDigit(character) &&
                        character is not ':' and not '.') ||
                selector.Contains('.') &&
                !TryCanonicalizeIpv4Literal(
                    selector[(selector.LastIndexOf(':') + 1)..],
                    out _))
            {
                canonicalSelector = string.Empty;
                return false;
            }

            if (IPAddress.TryParse(selector, out IPAddress? address) &&
                address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                canonicalSelector = address.ToString();
                return true;
            }

            canonicalSelector = string.Empty;
            return false;
        }

        return TryCanonicalizeIpv4Literal(
            selector,
            out canonicalSelector);
    }

    private static bool TryCanonicalizeIpv4Literal(
        string selector,
        out string canonicalSelector)
    {
        string[] octets = selector.Split('.');
        if (octets.Length != 4)
        {
            canonicalSelector = string.Empty;
            return false;
        }

        var values = new byte[octets.Length];
        for (int index = 0; index < octets.Length; index++)
        {
            string octet = octets[index];
            if (octet.Length == 0 ||
                octet.Length > 1 && octet[0] == '0' ||
                !octet.All(char.IsAsciiDigit) ||
                !byte.TryParse(
                    octet,
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out values[index]))
            {
                canonicalSelector = string.Empty;
                return false;
            }
        }

        canonicalSelector = string.Create(
            CultureInfo.InvariantCulture,
            $"{values[0]}.{values[1]}.{values[2]}.{values[3]}");
        return true;
    }

    private static bool IsDecoratedIpv6AddressCandidate(string selector)
    {
        return selector.Count(character => character == ':') >= 2 &&
            selector.Any(
                character =>
                    character is '%' or '[' or ']' or '/' or '\\' or '?' or '#');
    }

    private static void RecordTargetError(
        DiagnosticErrorLedger errors,
        string code,
        int targetIndex,
        DateTimeOffset occurredAt)
    {
        errors.Record(
            DiagnosticErrorCategory.Capture,
            code,
            $"Capture target at index {targetIndex} could not be resolved uniquely and safely.",
            occurredAt);
    }
}
