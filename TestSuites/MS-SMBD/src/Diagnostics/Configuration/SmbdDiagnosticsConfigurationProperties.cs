// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Configuration;

public static class SmbdDiagnosticsConfigurationProperties
{
    public const string ClientRNicIp = "ClientRNicIp";

    public static DiagnosticsConfigurationPropertyMap PropertyMap { get; } =
        new(
            DiagnosticsConfigurationPropertyNames.Enabled,
            DiagnosticsConfigurationPropertyNames.ArtifactRoot,
            DiagnosticsConfigurationPropertyNames.Provider,
            DiagnosticsConfigurationPropertyNames.ToolPath,
            DiagnosticsConfigurationPropertyNames.Targets,
            DiagnosticsConfigurationPropertyNames.TrafficScope,
            DiagnosticsConfigurationPropertyNames.StartTimeout,
            DiagnosticsConfigurationPropertyNames.StopTimeout,
            DiagnosticsConfigurationPropertyNames.MaxDuration,
            DiagnosticsConfigurationPropertyNames.MaxBytes,
            DiagnosticsConfigurationPropertyNames.Format,
            DiagnosticsConfigurationPropertyNames.NativeLogsEnabled,
            DiagnosticsConfigurationPropertyNames.Retention,
            ClientRNicIp);
}
