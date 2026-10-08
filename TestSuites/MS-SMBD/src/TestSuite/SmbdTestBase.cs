// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocol.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestSuites.Smbd.Adapter;
using Microsoft.Protocols.TestSuites.Diagnostics.Lifecycle;
using Microsoft.Protocols.TestSuites.Diagnostics.Runner;
using Microsoft.Protocols.TestSuites.Smbd.Diagnostics.Ptf;
using Microsoft.Protocols.TestTools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace Microsoft.Protocol.TestSuites.Smbd.TestSuite
{
    [TestClass]
    public class SmbdTestBase : TestClassBase, IDisposable
    {
        #region Variables
        private ISutProtocolControlAdapter sutProtocolControlAdapter;
        private DiagnosticsInvocationLifecycle diagnosticsLifecycle;
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
            diagnosticsLifecycle = PtfDiagnosticsLifecycle.Start(
                BaseTestSite.Properties,
                BaseTestSite.TestProperties,
                BaseTestSite.Log,
                Path.GetDirectoryName(GetType().Assembly.Location) ??
                    AppContext.BaseDirectory,
                CreateRunnerTestExecutionIdentity);
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
                if (cleanupCompleted)
                {
                    diagnosticsLifecycle?.MarkCleanupCompleted();
                }
                else
                {
                    diagnosticsLifecycle?.MarkCleanupFailed();
                }
            }
        }
        #endregion

        public void Dispose()
        {
            DiagnosticsInvocationLifecycle lifecycle =
                Interlocked.Exchange(ref diagnosticsLifecycle, null);
            if (lifecycle == null)
            {
                return;
            }

            lifecycle.Dispose();
            foreach (var error in lifecycle.Errors.Chronology)
            {
                BaseTestSite.Log.Add(
                    LogEntryKind.Warning,
                    "MS-SMBD diagnostics {0}: {1}",
                    error.Code,
                    error.Message);
            }
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

        private RunnerTestExecutionIdentity CreateRunnerTestExecutionIdentity()
        {
            string currentTestCaseName =
                (string)BaseTestSite.TestProperties["CurrentTestCaseName"];
            int methodSeparator = currentTestCaseName.LastIndexOf('.');
            string fallbackType = currentTestCaseName[..methodSeparator];
            string fallbackMethod = currentTestCaseName[(methodSeparator + 1)..];
            return new RunnerTestExecutionIdentity(
                TestContext?.ManagedType ?? fallbackType,
                TestContext?.ManagedMethod ?? fallbackMethod,
                TestContext?.TestDisplayName ??
                    TestContext?.TestName ??
                    currentTestCaseName,
                TestContext?.TestRunCount ?? 0);
        }
        #endregion
    }
}