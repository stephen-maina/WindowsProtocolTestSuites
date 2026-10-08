// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Specialized;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;

public sealed class PtfEffectiveConfigurationSource : IEffectiveConfigurationSource
{
    private readonly NameValueCollection properties;

    public PtfEffectiveConfigurationSource(NameValueCollection properties)
    {
        this.properties = properties ?? throw new ArgumentNullException(nameof(properties));
    }

    public string? GetValue(string propertyName)
    {
        if (string.IsNullOrWhiteSpace(propertyName))
        {
            throw new ArgumentException("A property name is required.", nameof(propertyName));
        }

        return properties[propertyName];
    }
}
