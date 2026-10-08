// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Storage;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Runner;

public static class SmbdRunnerContext
{
    public const string RunIdEnvironmentVariable =
        "SMBD_DIAGNOSTICS_RUN_ID";

    public static string? ReadRunId()
    {
        string? value = Environment.GetEnvironmentVariable(
            RunIdEnvironmentVariable);
        return string.IsNullOrEmpty(value) ? null : value;
    }

    public static string FindSourceRoot(string buildOutputRoot)
    {
        return ArtifactStorageBoundaries.FindSourceRoot(buildOutputRoot);
    }
}
