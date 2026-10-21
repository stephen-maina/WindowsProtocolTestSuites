// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Tests.Configuration;

internal sealed class TestEffectiveConfigurationSource : IEffectiveConfigurationSource
{
    private readonly IReadOnlyDictionary<string, string?> values;
    private readonly Action<string>? onRead;

    public TestEffectiveConfigurationSource(
        IReadOnlyDictionary<string, string?> values,
        Action<string>? onRead = null)
    {
        this.values = values;
        this.onRead = onRead;
    }

    public List<string> RequestedProperties { get; } = new();

    public string? GetValue(string propertyName)
    {
        RequestedProperties.Add(propertyName);
        onRead?.Invoke(propertyName);
        return values.TryGetValue(propertyName, out string? value)
            ? value
            : null;
    }
}
