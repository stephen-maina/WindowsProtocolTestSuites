// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Diagnostics.Ptf;
using Microsoft.Protocols.TestTools;
using System;
using System.IO;

namespace Microsoft.Protocols.TestSuites.FileSharing.Common.TestSuite
{
    /// <summary>
    /// WHAT: PtfTestClassBase that also runs the shared per-test diagnostics (packet capture, SUT log window).
    /// WHY: FSA and the model-based suites (FSAModel, SMB2Model) derive from PtfTestClassBase, not CommonTestBase,
    /// and their generated classes cannot be edited. Every one of them calls InitializeTestManager at the start of
    /// TestInitialize and CleanupTestManager at the end of TestCleanup, so those virtual methods are the hook.
    /// SPEC: Not protocol behaviour; debugging aid only.
    /// </summary>
    public abstract class FileServerPtfTestClassBase : PtfTestClassBase
    {
        private PtfTestDiagnostics diagnostics;

        public override void InitializeTestManager()
        {
            base.InitializeTestManager();
            diagnostics = PtfTestDiagnostics.Begin(
                BaseTestSite,
                FileServerDiagnosticsSuite.Definition,
                Path.GetDirectoryName(GetType().Assembly.Location) ?? AppContext.BaseDirectory,
                FileServerDiagnosticsSuite.SutProperties,
                TestContext?.ManagedType,
                TestContext?.ManagedMethod,
                TestContext?.TestDisplayName ?? TestContext?.TestName,
                TestContext?.TestRunCount);
        }

        public override void CleanupTestManager()
        {
            try
            {
                diagnostics?.End(true);
                diagnostics?.Dispose();
                diagnostics = null;
            }
            finally
            {
                base.CleanupTestManager();
            }
        }
    }
}
