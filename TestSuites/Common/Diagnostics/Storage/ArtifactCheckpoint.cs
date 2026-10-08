// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Security;
using System.Text;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Storage;

public sealed class ArtifactCheckpoint : IDisposable
{
    private readonly string rootPath;
    private bool _committed;
    private bool _disposed;

    internal ArtifactCheckpoint(string rootPath, string finalPath, string stagingPath)
    {
        this.rootPath = rootPath;
        FinalPath = finalPath;
        StagingPath = stagingPath;
    }

    public string FinalPath { get; }

    public string StagingPath { get; }

    public void WriteText(string content)
    {
        EnsureActive();
        ArgumentNullException.ThrowIfNull(content);

        try
        {
            ArtifactPath.EnsureNoReparsePoints(rootPath, StagingPath);
            using FileStream stream = new(
                StagingPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.WriteThrough);
            using StreamWriter writer = new(
                stream,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                bufferSize: 4096,
                leaveOpen: true);
            writer.Write(content);
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw CreateWriteException(exception);
        }
        catch (IOException exception)
        {
            throw CreateWriteException(exception);
        }
        catch (NotSupportedException exception)
        {
            throw CreateWriteException(exception);
        }
        catch (SecurityException exception)
        {
            throw CreateWriteException(exception);
        }
    }

    public void Commit()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(ArtifactCheckpoint));
        }

        if (_committed)
        {
            return;
        }

        if (!File.Exists(StagingPath))
        {
            throw new InvalidOperationException(
                $"Checkpoint staging file '{StagingPath}' does not exist.");
        }

        try
        {
            ArtifactPath.EnsureNoReparsePoints(rootPath, StagingPath);
            ArtifactPath.EnsureNoReparsePoints(rootPath, FinalPath);
            File.Move(StagingPath, FinalPath, overwrite: true);
            _committed = true;
        }
        catch (UnauthorizedAccessException exception)
        {
            throw CreateCommitException(exception);
        }
        catch (IOException exception)
        {
            throw CreateCommitException(exception);
        }
        catch (NotSupportedException exception)
        {
            throw CreateCommitException(exception);
        }
        catch (SecurityException exception)
        {
            throw CreateCommitException(exception);
        }
    }

    public void Dispose()
    {
        _disposed = true;
    }

    private ArtifactStorageException CreateWriteException(Exception exception)
    {
        return new ArtifactStorageException(
            ArtifactStorageFailure.NotWritable,
            $"Checkpoint staging file '{StagingPath}' could not be written.",
            exception);
    }

    private ArtifactStorageException CreateCommitException(Exception exception)
    {
        return new ArtifactStorageException(
            ArtifactStorageFailure.NotWritable,
            $"Checkpoint staging file '{StagingPath}' could not be committed to '{FinalPath}'.",
            exception);
    }

    private void EnsureActive()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(ArtifactCheckpoint));
        }

        if (_committed)
        {
            throw new InvalidOperationException("A committed checkpoint cannot be rewritten.");
        }
    }
}
