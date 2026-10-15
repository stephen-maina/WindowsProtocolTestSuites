// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Diagnostics.Ptf;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Runner;

namespace Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;

/// <summary>
/// The MS-SMBD specifics of the shared PTF diagnostics: its property map (RDMA NIC as capture target) and the
/// run id published by the MS-SMBD diagnostics runner.
/// </summary>
public static class SmbdDiagnosticsSuite
{
    public static PtfDiagnosticsSuite Definition { get; } = new(
        "MS-SMBD",
        SmbdDiagnosticsConfigurationProperties.PropertyMap,
        SmbdRunnerContext.ReadRunId);
}
