// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Protocols.TestSuites.Diagnostics.Providers;

public enum DiagnosticsRuntimePlatform
{
    Windows,
    Linux,
    Unsupported,
}

public static class DiagnosticsRuntimePlatformDetector
{
    public static DiagnosticsRuntimePlatform Detect()
    {
        if (OperatingSystem.IsWindows())
        {
            return DiagnosticsRuntimePlatform.Windows;
        }

        if (OperatingSystem.IsLinux())
        {
            return DiagnosticsRuntimePlatform.Linux;
        }

        return DiagnosticsRuntimePlatform.Unsupported;
    }
}
