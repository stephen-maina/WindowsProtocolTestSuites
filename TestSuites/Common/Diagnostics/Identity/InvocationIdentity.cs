// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Text;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Identity;

public sealed class InvocationIdentity
{
    private const int MaximumDisplayNameLength = 64;

    private InvocationIdentity(
        string runId,
        string testIdentity,
        string attemptIdentity,
        string dataRowIdentity,
        string opaqueInvocationId,
        string displayName,
        string? managedTestIdentitySha256,
        string? testDisplayNameSha256)
    {
        RunId = runId;
        TestIdentity = testIdentity;
        AttemptIdentity = attemptIdentity;
        DataRowIdentity = dataRowIdentity;
        OpaqueInvocationId = opaqueInvocationId;
        DisplayName = displayName;
        DirectoryName = $"{displayName}__{opaqueInvocationId}";
        ManagedTestIdentitySha256 = managedTestIdentitySha256;
        TestDisplayNameSha256 = testDisplayNameSha256;
    }

    public string RunId { get; }

    public string TestIdentity { get; }

    public string AttemptIdentity { get; }

    public string DataRowIdentity { get; }

    public string OpaqueInvocationId { get; }

    public string InvocationId => OpaqueInvocationId;

    public string DisplayName { get; }

    public string DirectoryName { get; }

    public string? ManagedTestIdentitySha256 { get; }

    public string? TestDisplayNameSha256 { get; }

    public static InvocationIdentity Create(
        string runId,
        string testIdentity,
        string attemptIdentity,
        string dataRowIdentity)
    {
        ArgumentNullException.ThrowIfNull(runId);
        ArgumentNullException.ThrowIfNull(testIdentity);
        ArgumentNullException.ThrowIfNull(attemptIdentity);
        ArgumentNullException.ThrowIfNull(dataRowIdentity);

        string opaqueInvocationId = Guid.NewGuid().ToString("N");
        string displayName = CreateDisplayName(testIdentity);

        return new InvocationIdentity(
            runId,
            testIdentity,
            attemptIdentity,
            dataRowIdentity,
            opaqueInvocationId,
            displayName,
            managedTestIdentitySha256: null,
            testDisplayNameSha256: null);
    }

    public static InvocationIdentity CreateCorrelated(
        string runId,
        string testIdentity,
        string attemptIdentity,
        string dataRowIdentity,
        string managedTestIdentitySha256,
        string testDisplayNameSha256)
    {
        ValidateSha256(
            managedTestIdentitySha256,
            nameof(managedTestIdentitySha256));
        ValidateSha256(
            testDisplayNameSha256,
            nameof(testDisplayNameSha256));

        InvocationIdentity identity = Create(
            runId,
            testIdentity,
            attemptIdentity,
            dataRowIdentity);
        return new InvocationIdentity(
            identity.RunId,
            identity.TestIdentity,
            identity.AttemptIdentity,
            identity.DataRowIdentity,
            identity.OpaqueInvocationId,
            identity.DisplayName,
            managedTestIdentitySha256.ToUpperInvariant(),
            testDisplayNameSha256.ToUpperInvariant());
    }

    private static string CreateDisplayName(string testIdentity)
    {
        StringBuilder builder = new(Math.Min(testIdentity.Length, MaximumDisplayNameLength));

        foreach (char character in testIdentity)
        {
            if (builder.Length == MaximumDisplayNameLength)
            {
                break;
            }

            builder.Append(IsSafeDisplayCharacter(character) ? character : '_');
        }

        string displayName = builder.ToString().TrimEnd('.', ' ');
        if (displayName.Length == 0)
        {
            displayName = "test";
        }

        if (IsWindowsReservedDeviceName(displayName))
        {
            displayName = "_" + displayName;
            if (displayName.Length > MaximumDisplayNameLength)
            {
                displayName = displayName[..MaximumDisplayNameLength];
            }
        }

        return displayName;
    }

    private static bool IsSafeDisplayCharacter(char character)
    {
        return character is >= 'a' and <= 'z'
            or >= 'A' and <= 'Z'
            or >= '0' and <= '9'
            or '.'
            or '-'
            or '_';
    }

    private static bool IsWindowsReservedDeviceName(string name)
    {
        int extensionIndex = name.IndexOf('.', StringComparison.Ordinal);
        string stem = extensionIndex >= 0 ? name[..extensionIndex] : name;

        return stem.Equals("CON", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase)
            || IsNumberedDeviceName(stem, "COM")
            || IsNumberedDeviceName(stem, "LPT");
    }

    private static bool IsNumberedDeviceName(string stem, string prefix)
    {
        return stem.Length == prefix.Length + 1
            && stem.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            && stem[^1] is >= '1' and <= '9';
    }

    private static void ValidateSha256(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (value.Length != 64 ||
            value.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException(
               "A SHA-256 digest must contain exactly 64 hexadecimal characters.",
               parameterName);
        }
    }
}
