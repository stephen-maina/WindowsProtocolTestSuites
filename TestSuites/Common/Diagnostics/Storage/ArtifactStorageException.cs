// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Storage;

public enum ArtifactStorageFailure
{
    RootRequired,
    RootMustBeAbsolute,
    RootInsideSource,
    RootInsideBuildOutput,
    NotWritable,
    UnsafePathComponent,
    PathOutsideRoot,
    UnsupportedPathNamespace,
    ReparsePointNotAllowed,
    DiagnosticsDisabled,
    ArtifactRootRequired = RootRequired,
    ArtifactRootMustBeAbsolute = RootMustBeAbsolute,
    ArtifactRootConflictsWithSource = RootInsideSource,
    ArtifactRootConflictsWithBuild = RootInsideBuildOutput,
    ArtifactRootNotWritable = NotWritable,
}

public sealed class ArtifactStorageException : Exception
{
    public ArtifactStorageException(ArtifactStorageFailure failure, string message)
        : base(message)
    {
        Failure = failure;
    }

    public ArtifactStorageException(
        ArtifactStorageFailure failure,
        string message,
        Exception innerException)
        : base(message, innerException)
    {
        Failure = failure;
    }

    public ArtifactStorageFailure Failure { get; }
}
