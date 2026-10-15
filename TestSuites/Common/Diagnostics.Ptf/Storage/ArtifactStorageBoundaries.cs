// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Storage;

public static class ArtifactStorageBoundaries
{
    public static string FindSourceRoot(string buildOutputRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(buildOutputRoot);

        DirectoryInfo current =
            new(Path.GetFullPath(buildOutputRoot));
        while (current.Parent is not null)
        {
            if (string.Equals(
                    current.Name,
                    "bin",
                    StringComparison.OrdinalIgnoreCase))
            {
                return current.Parent.FullName;
            }

            current = current.Parent;
        }

        return Path.GetFullPath(buildOutputRoot);
    }
}
