// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Diagnostics.Configuration;
using Microsoft.Protocols.TestSuites.Diagnostics.Ptf;
using Microsoft.Protocols.TestSuites.Diagnostics.Sut;

namespace Microsoft.Protocols.TestSuites.FileSharing.Common.TestSuite
{
    /// <summary>
    /// The FileServer specifics of the shared PTF diagnostics: which ptfconfig properties name the SUT and its
    /// credentials, and which client NIC is the capture target when Diagnostics.Capture.Targets is not set.
    /// Everything else (lifecycle, artifact layout, SUT log window) is the shared code.
    /// </summary>
    public static class FileServerDiagnosticsSuite
    {
        public static PtfDiagnosticsSuite Definition { get; } = new PtfDiagnosticsSuite(
            "FileServer",
            new DiagnosticsConfigurationPropertyMap(
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
                "ClientNic1IPAddress"),
            propertyGroup: "Common");

        public static SutLogCollector.PropertyNames SutProperties { get; } =
            new SutLogCollector.PropertyNames(User: "AdminUserName", Password: "PasswordForAllUsers");
    }
}
