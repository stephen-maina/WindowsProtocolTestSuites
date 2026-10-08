// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Storage;

public static class ArtifactPath
{
    internal static StringComparer PathComparer =>
        CurrentPlatform == ArtifactPathPlatform.Windows
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;

    public static string CombineUnderRoot(string root, params string[] components)
    {
        string canonicalRoot = CanonicalizeAbsoluteRoot(root);
        ArgumentNullException.ThrowIfNull(components);

        if (components.Length == 0)
        {
            throw new ArgumentException("At least one path component is required.", nameof(components));
        }

        string candidate = canonicalRoot;
        foreach (string component in components)
        {
            ValidateComponent(component);
            candidate = Path.Combine(candidate, component);
        }

        candidate = Canonicalize(candidate);
        EnsureContained(canonicalRoot, candidate);
        return candidate;
    }

    public static bool IsContained(string root, string candidate)
    {
        string canonicalRoot = Canonicalize(root);
        string canonicalCandidate = Canonicalize(candidate);
        return IsContainedCanonical(
            canonicalRoot,
            canonicalCandidate,
            CurrentPlatform);
    }

    public static bool IsContainedCanonical(
        string canonicalRoot,
        string canonicalCandidate,
        ArtifactPathPlatform platform)
    {
        StringComparison comparison = platform == ArtifactPathPlatform.Windows
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (string.Equals(canonicalRoot, canonicalCandidate, comparison))
        {
            return false;
        }

        string childPrefix = EndsWithDirectorySeparator(canonicalRoot)
            ? canonicalRoot
            : canonicalRoot + GetDirectorySeparator(platform);

        return canonicalCandidate.StartsWith(childPrefix, comparison);
    }

    public static void EnsureContained(string root, string candidate)
    {
        if (!IsContained(root, candidate))
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.PathOutsideRoot,
                $"The artifact path '{candidate}' is outside the configured root.");
        }
    }

    internal static string CanonicalizeAbsoluteRoot(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.RootRequired,
                "An explicit artifact root is required.");
        }

        EnsureSupportedPathNamespace(root);
        string normalized = NormalizeSeparators(root);
        if (!Path.IsPathFullyQualified(normalized))
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.RootMustBeAbsolute,
                $"The artifact root '{root}' must be an absolute path.");
        }

        try
        {
            return Canonicalize(normalized);
        }
        catch (ArgumentException exception)
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.RootMustBeAbsolute,
                $"The artifact root '{root}' is not a valid absolute path.",
                exception);
        }
        catch (NotSupportedException exception)
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.RootMustBeAbsolute,
                $"The artifact root '{root}' is not a valid absolute path.",
                exception);
        }
    }

    internal static string Canonicalize(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        EnsureSupportedPathNamespace(path);
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(NormalizeSeparators(path)));
    }

    internal static bool PathsEqual(string first, string second)
    {
        return string.Equals(
            Canonicalize(first),
            Canonicalize(second),
            CurrentPlatform == ArtifactPathPlatform.Windows
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal);
    }

    internal static string NormalizeRelativePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.UnsafePathComponent,
                "A non-empty relative artifact path is required.");
        }

        EnsureSupportedPathNamespace(path);
        string normalized = path.Replace('\\', '/');
        if (Path.IsPathRooted(path)
            || normalized.StartsWith("/", StringComparison.Ordinal)
            || (CurrentPlatform == ArtifactPathPlatform.Windows &&
                normalized.Contains(':', StringComparison.Ordinal)))
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.UnsafePathComponent,
                $"'{path}' is not a safe relative artifact path.");
        }

        string[] components = normalized.Split('/');
        foreach (string component in components)
        {
            ValidateComponent(component);
        }

        return string.Join("/", components);
    }

    internal static string ResolveRelativePathUnderRoot(string root, string relativePath)
    {
        string canonicalRoot = CanonicalizeAbsoluteRoot(root);
        string normalizedRelativePath = NormalizeRelativePath(relativePath);
        string candidate = Canonicalize(Path.Combine(
            canonicalRoot,
            normalizedRelativePath.Replace('/', Path.DirectorySeparatorChar)));
        EnsureContained(canonicalRoot, candidate);
        EnsureNoReparsePoints(canonicalRoot, candidate);
        return candidate;
    }

    internal static void EnsureNoReparsePoints(string root, string candidate)
    {
        string canonicalRoot = CanonicalizeAbsoluteRoot(root);
        string canonicalCandidate = Canonicalize(candidate);
        bool isRoot = string.Equals(
            canonicalRoot,
            canonicalCandidate,
            CurrentPlatform == ArtifactPathPlatform.Windows
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal);
        if (!isRoot)
        {
            EnsureContained(canonicalRoot, canonicalCandidate);
        }

        var ancestors = new Stack<string>();
        for (DirectoryInfo? directory = new(canonicalRoot);
             directory is not null;
             directory = directory.Parent)
        {
            ancestors.Push(directory.FullName);
        }

        while (ancestors.Count > 0)
        {
            EnsureExistingPathIsNotReparsePoint(ancestors.Pop());
        }

        if (isRoot)
        {
            return;
        }

        string relativePath = Path.GetRelativePath(canonicalRoot, canonicalCandidate);
        string current = canonicalRoot;
        foreach (string component in relativePath.Split(
                     new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            EnsureExistingPathIsNotReparsePoint(current);
        }
    }

    internal static void EnsureSupportedPathNamespace(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (CurrentPlatform != ArtifactPathPlatform.Windows)
        {
            return;
        }

        string windowsPath = path.Replace('/', '\\');
        if (windowsPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)
            || windowsPath.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase)
            || windowsPath.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.UnsupportedPathNamespace,
                $"The path namespace used by '{path}' is not supported.");
        }
    }

    internal static void ValidateComponent(string component)
    {
        ValidateComponent(component, CurrentPlatform);
    }

    public static void ValidateComponent(
        string component,
        ArtifactPathPlatform platform)
    {
        bool isValid = platform switch
        {
            ArtifactPathPlatform.Windows =>
                WindowsPathComponent.IsValid(component),
            ArtifactPathPlatform.Linux =>
                LinuxPathComponent.IsValid(component),
            _ => false,
        };
        if (!isValid)
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.UnsafePathComponent,
                $"'{component}' is not a safe artifact path component.");
        }
    }

    private static void EnsureExistingPathIsNotReparsePoint(string path)
    {
        if (!Directory.Exists(path) && !File.Exists(path))
        {
            return;
        }

        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.ReparsePointNotAllowed,
                $"Artifact paths must not traverse the reparse point '{path}'.");
        }
    }

    private static string NormalizeSeparators(string path)
    {
        return path
            .Replace('\\', Path.DirectorySeparatorChar)
            .Replace('/', Path.DirectorySeparatorChar);
    }

    private static bool EndsWithDirectorySeparator(string path)
    {
        return path.Length > 0
            && path[^1] is '/' or '\\';
    }

    private static ArtifactPathPlatform CurrentPlatform =>
        OperatingSystem.IsLinux()
            ? ArtifactPathPlatform.Linux
            : ArtifactPathPlatform.Windows;

    private static char GetDirectorySeparator(ArtifactPathPlatform platform)
    {
        return platform == ArtifactPathPlatform.Windows ? '\\' : '/';
    }
}
