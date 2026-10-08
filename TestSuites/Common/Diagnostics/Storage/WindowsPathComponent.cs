// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Storage;

internal static class WindowsPathComponent
{
    private const int MaximumLength = 255;

    internal static bool IsValid(string component)
    {
        return !string.IsNullOrEmpty(component)
            && component.Length <= MaximumLength
            && component is not "." and not ".."
            && !component.EndsWith(".", StringComparison.Ordinal)
            && !component.EndsWith(" ", StringComparison.Ordinal)
            && !Path.IsPathRooted(component)
            && !ContainsSeparator(component)
            && !ContainsInvalidCharacter(component)
            && !IsReservedDeviceName(component);
    }

    private static bool ContainsSeparator(string component)
    {
        return component.Contains('\\', StringComparison.Ordinal)
            || component.Contains('/', StringComparison.Ordinal);
    }

    private static bool ContainsInvalidCharacter(string component)
    {
        foreach (char character in component)
        {
            if (char.IsControl(character) ||
                character is '<' or '>' or ':' or '"' or '|' or '?' or '*')
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsReservedDeviceName(string component)
    {
        int extensionIndex = component.IndexOf('.', StringComparison.Ordinal);
        string stem = extensionIndex >= 0 ? component[..extensionIndex] : component;

        return stem.Equals("CON", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase)
            || IsNumberedDeviceName(stem, "COM")
            || IsNumberedDeviceName(stem, "LPT");
    }

    private static bool IsNumberedDeviceName(string stem, string prefix)
    {
        if (stem.Length != prefix.Length + 1 ||
            !stem.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return stem[^1] is >= '1' and <= '9'
            or '\u00B9'
            or '\u00B2'
            or '\u00B3';
    }
}
