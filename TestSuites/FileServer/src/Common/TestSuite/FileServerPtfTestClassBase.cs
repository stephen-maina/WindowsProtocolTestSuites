// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestSuites.Diagnostics.Ptf;
using Microsoft.Protocols.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace Microsoft.Protocols.TestSuites.FileSharing.Common.TestSuite
{
    /// <summary>
    /// WHAT: PtfTestClassBase that also runs the shared per-test diagnostics (packet capture, SUT log window).
    /// WHY: FSA and the model-based suites (FSAModel, SMB2Model) derive from PtfTestClassBase, not CommonTestBase,
    /// and their generated cleanup can fail before reaching CleanupTestManager. The MSTest boundary wraps the
    /// PTF dispatcher so diagnostics close even after failed acquisition or adapter reset.
    /// SPEC: Not protocol behaviour; debugging aid only.
    /// </summary>
    public abstract class FileServerPtfTestClassBase : PtfTestClassBase
    {
        private PtfTestDiagnostics diagnostics;
        private bool cleanupManagerCompleted;

        public override void InitializeTestManager()
        {
            base.InitializeTestManager();
            cleanupManagerCompleted = false;
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
            base.CleanupTestManager();
            cleanupManagerCompleted = true;
        }

        [TestCleanup]
        public new void BaseTestCleanup()
        {
            bool cleanupCompleted = false;
            try
            {
                base.BaseTestCleanup();
                cleanupCompleted = true;
            }
            finally
            {
                PtfTestDiagnostics current = diagnostics;
                diagnostics = null;
                try
                {
                    current?.End(cleanupCompleted && cleanupManagerCompleted);
                }
                catch (Exception)
                {
                    // Diagnostics must not replace the PTF setup, test or cleanup exception.
                }
                finally
                {
                    try { current?.Dispose(); }
                    catch (Exception) { }
                }
            }
        }
    }
}
