// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using Microsoft.Protocols.TestSuites.Diagnostics.Identity;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Storage;

public sealed class ArtifactStore : IDisposable
{
    private ArtifactStore(bool isEnabled, string rootPath)
    {
        IsEnabled = isEnabled;
        RootPath = rootPath;
    }

    public bool IsEnabled { get; }

    public string RootPath { get; }

    public static ArtifactStore Open(
        string root,
        string sourceRoot,
        string buildOutputRoot)
    {
        string canonicalRoot = ArtifactPath.CanonicalizeAbsoluteRoot(root);
        string canonicalSourceRoot = CanonicalizeRequiredAbsolutePath(sourceRoot, nameof(sourceRoot));
        string canonicalBuildRoot = CanonicalizeRequiredAbsolutePath(buildOutputRoot, nameof(buildOutputRoot));

        if (ArtifactPath.PathsEqual(canonicalRoot, canonicalBuildRoot)
            || ArtifactPath.IsContained(canonicalBuildRoot, canonicalRoot))
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.RootInsideBuildOutput,
                "The artifact root must not equal or be contained by the build output root.");
        }

        if (ArtifactPath.PathsEqual(canonicalRoot, canonicalSourceRoot)
            || ArtifactPath.IsContained(canonicalSourceRoot, canonicalRoot))
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.RootInsideSource,
                "The artifact root must not equal or be contained by the source root.");
        }

        CreateAndProbeRoot(canonicalRoot);
        return new ArtifactStore(isEnabled: true, canonicalRoot);
    }

    public static ArtifactStore CreateDisabled(string configuredRoot)
    {
        ArgumentNullException.ThrowIfNull(configuredRoot);
        return new ArtifactStore(isEnabled: false, configuredRoot);
    }

    public ArtifactInvocation CreateInvocation(InvocationIdentity identity)
    {
        EnsureEnabled();
        ArgumentNullException.ThrowIfNull(identity);

        string invocationRoot = ArtifactPath.CombineUnderRoot(RootPath, identity.DirectoryName);
        ArtifactPath.EnsureNoReparsePoints(RootPath, invocationRoot);
        CreateDirectoryCore(invocationRoot);
        ArtifactPath.EnsureNoReparsePoints(RootPath, invocationRoot);
        return new ArtifactInvocation(invocationRoot);
    }

    public string CreateInvocationRoot(InvocationIdentity identity)
    {
        using ArtifactInvocation invocation = CreateInvocation(identity);
        return invocation.DirectoryPath;
    }

    public string CreateDirectory(params string[] components)
    {
        EnsureEnabled();
        string path = ArtifactPath.CombineUnderRoot(RootPath, components);
        ArtifactPath.EnsureNoReparsePoints(RootPath, path);
        CreateDirectoryCore(path);
        ArtifactPath.EnsureNoReparsePoints(RootPath, path);
        return path;
    }

    public ArtifactCheckpoint CreateCheckpoint(params string[] components)
    {
        EnsureEnabled();
        return CreateCheckpointUnderRoot(RootPath, components);
    }

    public IReadOnlyList<string> EnumerateInterruptedCheckpoints()
    {
        EnsureEnabled();
        return FindInterruptedCheckpointsUnderRoot(RootPath);
    }

    public void Dispose()
    {
    }

    internal static ArtifactCheckpoint CreateCheckpointUnderRoot(
        string rootPath,
        params string[] components)
    {
        string finalPath = ArtifactPath.CombineUnderRoot(rootPath, components);
        ArtifactPath.EnsureNoReparsePoints(rootPath, finalPath);
        string? parentPath = Path.GetDirectoryName(finalPath);
        if (parentPath is null)
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.PathOutsideRoot,
                $"The final artifact path '{finalPath}' has no parent directory.");
        }

        CreateDirectoryCore(parentPath);
        ArtifactPath.EnsureNoReparsePoints(rootPath, finalPath);
        string stagingName = $".checkpoint-{Guid.NewGuid():N}.tmp";
        string stagingPath = ArtifactPath.CombineUnderRoot(parentPath, stagingName);
        ArtifactPath.EnsureNoReparsePoints(rootPath, stagingPath);

        return new ArtifactCheckpoint(rootPath, finalPath, stagingPath);
    }

    internal static IReadOnlyList<string> FindInterruptedCheckpointsUnderRoot(string rootPath)
    {
        try
        {
            var interrupted = new List<string>();
            var pendingDirectories = new Stack<string>();
            pendingDirectories.Push(rootPath);

            while (pendingDirectories.Count > 0)
            {
                string directory = pendingDirectories.Pop();
                ArtifactPath.EnsureNoReparsePoints(rootPath, directory);
                foreach (string checkpoint in Directory.EnumerateFiles(
                             directory,
                             "*.checkpoint-*.tmp",
                             SearchOption.TopDirectoryOnly))
                {
                    ArtifactPath.EnsureNoReparsePoints(rootPath, checkpoint);
                    interrupted.Add(checkpoint);
                }

                foreach (string child in Directory.EnumerateDirectories(
                             directory,
                             "*",
                             SearchOption.TopDirectoryOnly))
                {
                    ArtifactPath.EnsureNoReparsePoints(rootPath, child);
                    pendingDirectories.Push(child);
                }
            }

            return interrupted
                .OrderBy(path => path, ArtifactPath.PathComparer)
                .ToArray();
        }
        catch (UnauthorizedAccessException exception)
        {
            throw CreateNotWritableException(rootPath, exception);
        }
        catch (IOException exception)
        {
            throw CreateNotWritableException(rootPath, exception);
        }
        catch (SecurityException exception)
        {
            throw CreateNotWritableException(rootPath, exception);
        }
    }

    private static string CanonicalizeRequiredAbsolutePath(string path, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(path, parameterName);
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("The path must not be empty.", parameterName);
        }

        string canonicalPath;
        try
        {
            ArtifactPath.EnsureSupportedPathNamespace(path);
            canonicalPath = ArtifactPath.Canonicalize(path);
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException("The path is invalid.", parameterName, exception);
        }
        catch (NotSupportedException exception)
        {
            throw new ArgumentException("The path is invalid.", parameterName, exception);
        }

        if (!Path.IsPathFullyQualified(canonicalPath))
        {
            throw new ArgumentException("The path must be absolute.", parameterName);
        }

        return canonicalPath;
    }

    private static void CreateAndProbeRoot(string rootPath)
    {
        string probePath = ArtifactPath.CombineUnderRoot(
            rootPath,
            $".write-probe-{Guid.NewGuid():N}.tmp");

        try
        {
            ArtifactPath.EnsureNoReparsePoints(rootPath, rootPath);
            Directory.CreateDirectory(rootPath);
            ArtifactPath.EnsureNoReparsePoints(rootPath, rootPath);
            using FileStream stream = new(
                probePath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 1,
                FileOptions.WriteThrough);
            stream.WriteByte(0);
            stream.Flush(flushToDisk: true);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw CreateNotWritableException(rootPath, exception);
        }
        catch (IOException exception)
        {
            throw CreateNotWritableException(rootPath, exception);
        }
        catch (NotSupportedException exception)
        {
            throw CreateNotWritableException(rootPath, exception);
        }
        catch (SecurityException exception)
        {
            throw CreateNotWritableException(rootPath, exception);
        }
        finally
        {
            DeleteProbe(probePath, rootPath);
        }
    }

    private static void DeleteProbe(string probePath, string rootPath)
    {
        try
        {
            File.Delete(probePath);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw CreateNotWritableException(rootPath, exception);
        }
        catch (IOException exception)
        {
            throw CreateNotWritableException(rootPath, exception);
        }
        catch (SecurityException exception)
        {
            throw CreateNotWritableException(rootPath, exception);
        }
    }

    private static void CreateDirectoryCore(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw CreateNotWritableException(path, exception);
        }
        catch (IOException exception)
        {
            throw CreateNotWritableException(path, exception);
        }
        catch (NotSupportedException exception)
        {
            throw CreateNotWritableException(path, exception);
        }
        catch (SecurityException exception)
        {
            throw CreateNotWritableException(path, exception);
        }
    }

    private static ArtifactStorageException CreateNotWritableException(
        string path,
        Exception exception)
    {
        return new ArtifactStorageException(
            ArtifactStorageFailure.NotWritable,
            $"The artifact location '{path}' is not writable.",
            exception);
    }

    private void EnsureEnabled()
    {
        if (!IsEnabled)
        {
            throw new ArtifactStorageException(
                ArtifactStorageFailure.DiagnosticsDisabled,
                "Artifact storage is disabled.");
        }
    }
}
