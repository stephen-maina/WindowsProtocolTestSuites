// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Linq;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Storage;

internal static class LinuxPathComponent
{
    private const int MaximumLength = 255;

    internal static bool IsValid(string component)
    {
        return !string.IsNullOrEmpty(component)
            && component.Length <= MaximumLength
            && component is not "." and not ".."
            && !component.Contains('/')
            && !component.Contains('\\')
            && !component.Any(char.IsControl);
    }
}
