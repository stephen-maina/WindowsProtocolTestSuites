// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Storage;

public sealed class ArtifactInvocation : IDisposable
{
    internal ArtifactInvocation(string directoryPath)
    {
        DirectoryPath = directoryPath;
    }

    public string DirectoryPath { get; }

    public ArtifactCheckpoint CreateCheckpoint(params string[] components)
    {
        return ArtifactStore.CreateCheckpointUnderRoot(DirectoryPath, components);
    }

    public IReadOnlyList<string> FindInterruptedCheckpoints()
    {
        return ArtifactStore.FindInterruptedCheckpointsUnderRoot(DirectoryPath);
    }

    public void Dispose()
    {
    }
}
