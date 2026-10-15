// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Ptf;

/// <summary>
/// The only things that differ between test suites that use the shared PTF diagnostics: the suite name used in
/// log messages and fallback identities, the configuration property names, and where a managed runner
/// publishes its run identifier. Everything else is shared.
/// </summary>
public sealed class PtfDiagnosticsSuite
{
    public PtfDiagnosticsSuite(
        string name,
        DiagnosticsConfigurationPropertyMap propertyMap,
        Func<string?>? readRunId = null,
        string? propertyGroup = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        Name = name;
        PropertyGroup = propertyGroup;
        PropertyMap = propertyMap ?? throw new ArgumentNullException(nameof(propertyMap));
        ReadRunId = readRunId ?? (() => null);
    }

    public string Name { get; }

    public DiagnosticsConfigurationPropertyMap PropertyMap { get; }

    public Func<string?> ReadRunId { get; }

    /// <summary>
    /// The ptfconfig group the suite's properties live in (PTF exposes them as "Group.Name"). When set, those
    /// entries are also made visible under their bare names, which is what the shared readers look up.
    /// </summary>
    public string? PropertyGroup { get; }

    public string UnknownInvocationName => Name + ".UnknownInvocation";

    public System.Collections.Specialized.NameValueCollection Flatten(System.Collections.Specialized.NameValueCollection properties)
    {
        if (string.IsNullOrEmpty(PropertyGroup))
        {
            return properties;
        }

        var flat = new System.Collections.Specialized.NameValueCollection(properties);
        string prefix = PropertyGroup + ".";
        foreach (string? key in properties.AllKeys)
        {
            if (key != null && key.StartsWith(prefix, StringComparison.Ordinal) && flat[key.Substring(prefix.Length)] == null)
            {
                flat[key.Substring(prefix.Length)] = properties[key];
            }
        }

        return flat;
    }
}
