// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocol.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestSuites.Diagnostics.Ptf;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;
using Microsoft.Protocols.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;

namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    [TestClass]
    public class SmbdTestBase : TestClassBase, IDisposable
    {
        #region Variables
        private ISutProtocolControlAdapter sutProtocolControlAdapter;
        private PtfTestDiagnostics diagnostics;
        protected SmbdAdapter smbdAdapter;
        protected List<string> fileNameList;

        /// <summary>
        /// SMBD parameters read from the ptfconfig file. Tests must use these instead of hardcoded values.
        /// </summary>
        protected TestConfig SmbdTestConfig
        {
            get { return smbdAdapter.TestConfig; }
        }
        #endregion

        #region Test Initialization and Cleanup
        protected override void TestInitialize()
        {
            base.TestInitialize();
            // WHAT/WHY: shared per-test diagnostics and SUT log window (best-effort, see PtfTestDiagnostics).
            // SPEC: not protocol behaviour.
            diagnostics = PtfTestDiagnostics.Begin(
                BaseTestSite,
                SmbdDiagnosticsSuite.Definition,
                Path.GetDirectoryName(GetType().Assembly.Location) ?? AppContext.BaseDirectory,
                managedType: TestContext?.ManagedType,
                managedMethod: TestContext?.ManagedMethod,
                displayName: TestContext?.TestDisplayName ?? TestContext?.TestName,
                runCount: TestContext?.TestRunCount);
            sutProtocolControlAdapter = BaseTestSite.GetAdapter<ISutProtocolControlAdapter>();
            this.smbdAdapter = new SmbdAdapter(BaseTestSite, LogSmbdEndpointEvent);
            fileNameList = new List<string>();
            SmbdUtilities.LogTestCaseDescription(BaseTestSite);
        }

        protected override void TestCleanup()
        {
            bool cleanupCompleted = false;
            try
            {
                foreach (string fileName in fileNameList)
                {
                    try
                    {
                        sutProtocolControlAdapter.DeleteFile(fileName);
                    }
                    catch
                    {

                    }
                }

                try
                {
                    smbdAdapter.DisconnectRdma();
                }
                catch
                {

                }

                smbdAdapter = null;

                base.TestCleanup();
                cleanupCompleted = true;
            }
            finally
            {
                diagnostics?.End(cleanupCompleted);
            }
        }
        #endregion

        public void Dispose()
        {
            diagnostics?.Dispose();
        }

        #region Protected Method
        protected string CreateRandomFileName()
        {
            string fileName = SmbdUtilities.CreateRandomFileName();
            fileNameList.Add(fileName);
            return fileName;
        }

        protected void LogSmbdEndpointEvent(string log)
        {
            BaseTestSite.Log.Add(
                LogEntryKind.Debug,
                log);
        }
        #endregion
    }
}