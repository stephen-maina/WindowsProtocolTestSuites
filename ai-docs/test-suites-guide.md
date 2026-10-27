# Test Suites Guide

## Overview

There are approximately 2,981 `[TestMethod]`-attributed test cases spread across 375 test files in this repository. Each test suite exercises a specific protocol family against a live System Under Test (SUT).

All test suites:
- Use **MSTest v2** (`Microsoft.VisualStudio.TestTools.UnitTesting`)
- Reference **Protocol Test Framework v2.6** (`Microsoft.Protocols.TestTools`) as a NuGet package
- Use `.ptfconfig` XML files for environment configuration
- Follow a consistent class hierarchy: `TestClassBase` (PTF) → suite-specific base → protocol-specific base → test class

## Test Class Hierarchy

```
TestClassBase (PTF NuGet)
└── CommonTestBase (FileServer) / RdpTestClassBase (RDP) / TraditionTestBase (Kerberos) / etc.
    └── SMB2TestBase / FsaTestBase / RdpbcgrTestBase / etc.
        └── Negotiation / BasicFileIO / Rdpbcgr_ClientTestSuite / etc.
```

`TestClassBase` provides:
- `BaseTestSite` (the PTF `ITestSite`) — logging, assertions, adapter resolution
- `TestClassBase.Initialize(TestContext)` — must be called from `[ClassInitialize]`
- `TestClassBase.Cleanup()` — must be called from `[ClassCleanup]`
- Virtual `TestInitialize()` and `TestCleanup()` called before/after each test

## Test Suite Anatomy

Every test suite directory under `TestSuites/<Name>/src/` has:

```
src/
├── build.ps1           Build and publish script
├── build.sh            Linux build script
├── <Suite>.sln         Solution file
├── Common/             (if multi-project) Shared adapter and config types
│   ├── Adapter/        Adapter interfaces and implementations
│   └── TestSuite/      CommonTestBase and shared config
├── <Protocol>/
│   ├── TestSuite/      [TestMethod] classes
│   └── Adapter/        Protocol-specific adapter (if present)
├── Batch/              .ps1 and .sh batch runner scripts
├── Deploy/             Deployment artifacts (license, etc.)
└── Plugin/             PTM auto-detection plugin
```

---

## FileServer Test Suite

**Path:** `TestSuites/FileServer/src/`
**Solution:** `FileServer.sln`
**Protocols tested:** MS-SMB2, MS-DFSC, MS-SWN, MS-FSRVP, MS-FSA, MS-FSCC, MS-RSVD, MS-SQOS

### Structure

```
FileServer/src/
├── Common/Adapter/     Smb2FunctionalClient, ISutCommonControlAdapter, ISutProtocolControlAdapter
├── Common/TestSuite/   CommonTestBase, CommonTypes, ptfconfig
├── Common/Diagnostics.Portability.Tests/
│                       Representative consumer tests for the suite-neutral diagnostics core
├── SMB2/TestSuite/     SMB2 test cases organized by feature area
├── SMB2/Adapter/       SMB2TestConfig
├── FSA/TestSuite/      File System Access (MS-FSA) test cases
├── DFSC/               DFS Referral test cases
├── FSRVP/              File Server Remote VSS test cases
├── RSVD/               Remote Shared Virtual Disk test cases
├── SQOS/               Storage Quality of Service test cases
├── ServerFailover/     Server failover scenarios
└── Auth/               Authentication test cases
```

### Azure Automation

`TestSuites/FileServer/azure-automation/` contains Bicep and PowerShell deployment entry points for Domain, Workgroup, and Cluster environments. Shared infrastructure belongs under `shared/modules/`; for example, `bastion.bicep` deploys Bastion independently from core networking so VM provisioning is not serialized behind it. Domain deployment separates member infrastructure (`domain-computers.bicep`) from guest extensions (`domain-computer-extensions.bicep`), allowing VM provisioning to overlap DC configuration while keeping domain join behind the DC readiness gate. On-VM orchestrators must reuse `shared/DSC/Deploy-CommonHelpers.ps1` and `Invoke-VerifiedDscConfiguration` rather than `Start-DscConfiguration -Wait`; fresh LCM status polling survives WinRM restarts and postcondition gates prevent stale completion signals or imperative setup against incomplete DSC state.

Workgroup and Domain use the deterministic phased model. Dedicated feature
configurations install disruptive roles before planned reboot boundaries;
convergence configurations contain only non-disruptive post-reboot state. The
Domain SUT persists `DomainSutDeployPhase` and coalesces feature servicing with
domain join into one normal reboot, then performs a separate bounded reboot
after forcing the AD and local machine secrets to the Auth suite's deterministic
`Password04!` service key. The DC persists `DcDeployPhase`, using one
foundation reboot for features/hostname and a separate mandatory promotion
reboot. The shared Driver prepares tools before its join reboot, then verifies
`PartOfDomain` and `Test-ComputerSecureChannel` before test setup. All roles use
atomic parallel package preparation, serial cached installation, concrete
postconditions, and heartbeat JSON files. Reuse phase, verified DSC, job-wait,
reboot-proof, and heartbeat helpers from `shared/DSC/Deploy-CommonHelpers.ps1`;
never continue through an unexpected pending reboot.

Cluster uses the same deterministic contracts through
`cluster-bicep/DSC/Deploy-ClusterNode.ps1`,
`cluster-bicep/DSC/Deploy-Storage.ps1`, and
`cluster-bicep/DSC/Deploy-ClusterDriver.ps1`. Node02 must publish foundation readiness
before Node01 forms the Cluster, and both nodes plus live Cluster/ForceLevel2
postconditions gate tests. Node01 uses the same shared Kerberos machine-password
alignment helper and proves its required reboot before publishing pre-cluster
readiness. `cluster-bicep/DSC/Scripts/Test-ClusterDriverReadiness.ps1` validates
the Auth service password/salt and forces Kerberos-only remoting to Node01 before
tests can start. Azure Cluster endpoints use a dual-subnet Standard
internal load balancer with floating-IP rules; do not map virtual names to a
physical owner node. Cluster node subnets use the scenario NAT Gateway because
ILB backend membership disables implicit outbound SNAT.

All deployment packages must use `shared/DSC/Scripts/Package-Contracts.ps1`.
`Build-DscPackage` writes and validates `PackageManifest.json`, and the packaged
bootstrap verifies scenario, required content, lengths, and SHA-256 hashes
before executing role scripts. Cluster packages fail closed if these integrity
contracts are absent.

FileServer releases use
`pipelines/1es/FileServer-Release-Orchestrator.yml`. The manual pipeline pins
the WPTS source to a full commit SHA, queues codesign pipeline 56330, verifies
the signed FileServer ZIP against its provenance sidecar, updates release URLs,
versions, and hashes only in staged `Tools.json` files, and emits one artifact
with the signed FileServer archive plus Workgroup, Domain, and Cluster OneClick
packages. Reuse
`TestSuites/FileServer/azure-automation/shared/Invoke-FileServerCodeSign.ps1`
and `pipelines/1es/templates/FileServer-OneClick-Package-Steps.yml` rather than
duplicating queueing, provenance validation, ESRP signing, or packaging logic.

The three one-click templates expose curated VM-size dropdowns through Bicep
`@allowed` values. Keep their burstable defaults and role-specific alternatives
aligned across Workgroup, Domain, and Cluster; the dropdowns improve selection
but do not guarantee transient Azure capacity.

Automatic FileServer test execution is controlled by the default-enabled
`enableTestAutoRun` deployment parameter. It is persisted in `Config.json` as
`TestExecution.AutoRun`; Driver orchestrators must remove stale test tasks and
skip scheduling when disabled, while deployment verification must not wait for
test signals. `SkipTestWait` only detaches local monitoring and must not be used
as an autorun control. Terminal deployment summaries report passed,
inconclusive (including `NotExecuted`), and failed outcomes separately; do not
label all non-passing tests as failures. Deployment terminals print only these
aggregate counts and the terminal classification; per-test messages and stack
traces remain in the local and uploaded result artifacts and must not be dumped
into the interactive deployment shell.

Deployment verification also bounds every Azure Run Command probe. A probe
timeout alone must not restart a VM because the server-side command can still
be completing. If the same Windows VM subsequently returns sustained HTTP 409
or "execution in progress" conflicts for at least five minutes, the shared
verifier performs at most one controlled restart to clear a wedged Guest Agent
operation, then resumes polling. Linux targets and conflicts without a
preceding local timeout are never restarted automatically.

Reuse these modules and helpers rather than embedding equivalent resources in scenario-specific scripts.

### Key Classes

| Class | File | Purpose |
|---|---|---|
| `CommonTestBase` | `Common/TestSuite/CommonTestBase.cs` | Abstract base; sets up adapters, cleans test files/dirs |
| `SMB2TestBase` | `SMB2/TestSuite/SMB2TestBase.cs` | Adds `SMB2TestConfig`, sets `DefaultProtocolDocShortName` |
| `Smb2FunctionalClient` | `Common/Adapter/Smb2FunctionalClient.cs` | High-level SMB2 client wrapping the raw ProtoSDK `Smb2Client` |
| `TestConfigBase` | `Common/Adapter/TestConfigBase.cs` | Reads `.ptfconfig` properties; base for all config classes |
| `SMB2TestConfig` | `SMB2/Adapter/SMB2TestConfig.cs` | SMB2-specific config (dialects, timeouts, etc.) |

### SMB2 Test Directories

| Directory | What it tests |
|---|---|
| `SMB2/TestSuite/Negotiate/` | Protocol negotiation, dialect selection |
| `SMB2/TestSuite/SessionMgmt/` | Session setup, logoff, reconnect |
| `SMB2/TestSuite/TreeMgmt/` | Tree connect/disconnect |
| `SMB2/TestSuite/CreateClose/` | File/directory create and close |
| `SMB2/TestSuite/Basic/` | Read, write, query info |
| `SMB2/TestSuite/Signing/` | Message signing |
| `SMB2/TestSuite/Encryption/` | Session/share-level encryption |
| `SMB2/TestSuite/DurableHandle/` | Durable open handles (v1 and v2) |
| `SMB2/TestSuite/Leasing/` | SMB2/3 leasing |
| `SMB2/TestSuite/OpLock/` | Opportunistic locks |
| `SMB2/TestSuite/MultipleChannel/` | Multi-channel scenarios |
| `SMB2/TestSuite/Compression/` | SMB3 compression |
| `SMB2/TestSuite/Replay/` | Replay protection |
| `SMB2/TestSuite/IOCTL/` | FSCTL operations |
| `SMB2/TestSuite/HVRS/` | Hyper-V replica set |
| `SMB2/TestSuite/AppInstanceId/` | Application instance identifier |
| `Auth/TestSuite/Authentication/` | Kerberos authentication and cross-mechanism (Kerberos/NTLM) encrypted post-authentication round trips (MS-SMB2 3.3.5.5.3, 3.2.5.3.1) |
| `Auth/TestSuite/Authorization/` | Share/folder/file permission checks and Claims-Based Access Control (CBAC) |

---

## RDP Test Suites

### RDP Client Test Suite

**Path:** `TestSuites/RDP/Client/src/`
**Solution:** `RDP_Client.sln`
**Protocols tested:** MS-RDPBCGR, MS-RDPEDISP, MS-RDPEDYC, MS-RDPEGFX, MS-RDPEGT, MS-RDPEI, MS-RDPEMT, MS-RDPEUDP, MS-RDPEUSB, MS-RDPEVOR, MS-RDPRFX

The RDP Client suite acts as the **RDP server** and tests the client. It uses `RDPSUTControlAgent` (a separate agent deployed on the SUT) to trigger client connections.

**Key Classes:**
- `RdpTestClassBase` (`TestSuite/RdpTestClassBase.cs`) — base class; initializes `TestConfig`, `IRDPSUTControlAdapter`

**Test directories in `TestSuite/`:**
`RDPBCGR/`, `RDPEDISP/`, `RDPEGFX/`, `RDPEI/`, `RDPEMT/`, `RDPEUDP/`, `RDPEUSB/`, `RDPEVOR/`, `RDPRFX/`

### RDP Server Test Suite

**Path:** `TestSuites/RDP/Server/src/`
**Solution:** `RDP_Server.sln`
**Protocols tested:** MS-RDPBCGR, MS-RDPEDYC, MS-RDPEMT, MS-RDPELE

The RDP Server suite acts as the **RDP client** and tests the server.

**Key Classes:**
- `RdpTestClassBase` (`TestSuite/RdpTestClassBase.cs`) — same base class as client suite

**Test directories:** `RDPBCGR/`, `RDPEDYC/`, `RDPELE/`, `RDPEMT/`

---

## Kerberos Test Suite

**Path:** `TestSuites/Kerberos/src/`
**Solution:** `Kerberos_Server.sln`
**Protocols tested:** MS-KILE, MS-KKDCP, MS-PAC

**Structure:**
```
src/
├── Adapter/        KerberosTestConfig, KerberosAdapter
├── TestSuite/
│   ├── TraditionTestBase.cs   Base class
│   ├── KILE/                  MS-KILE test cases
│   ├── KKDCP/                 MS-KKDCP (Kerberos proxy) test cases
│   ├── RC4/                   RC4 encryption tests
│   ├── Claim/                 Claims-based authorization tests
│   └── AZOD/                  Azure Object Discovery tests
```

**Key Classes:**
- `TraditionTestBase` — sets up KerberosAdapter and test site
- Playlists (`.PLAYLIST` files) define which tests to run for specific OS/domain configurations (e.g., `SingleRealm_KDC_2012R2.PLAYLIST`)

---

## MS-SMBD Test Suite

**Path:** `TestSuites/MS-SMBD/src/`
**Solution:** `MS-SMBD_Server.sln`
**Protocols tested:** MS-SMBD (SMB2 over RDMA), MS-SMB2

**Structure:**
```
src/
├── Adapter/
│   ├── SmbdAdapter.cs          Main SMBD adapter
│   ├── Smb2OverSmbdTestClient.cs
│   └── TestConfig.cs
├── Diagnostics/                 Thin MS-SMBD PTF integration and provider selection
├── Diagnostics.Tests/           Managed diagnostics regression coverage
├── Diagnostics.Runner/          Test execution and evidence reconciliation
└── TestSuite/
    ├── SmbdTestBase.cs         Base for pure SMBD tests
    ├── Smb2OverSmbdTestBase.cs Base for SMB2-over-SMBD tests
    ├── SMBD/                   SMBD connection/negotiation tests
    └── SMB2overSMBD/           SMB2 operations carried over SMBD
```

Requires an RDMA-capable NIC on both client and server. For Windows: uses the C++/CLI `RDMA` adapter in ProtoSDK. For Linux: uses the `RdmaLinux` adapter.

### Shared Diagnostics Evidence Infrastructure

The reusable diagnostics implementation is in
`TestSuites/Common/Diagnostics/`, outside any protocol-specific suite. It
provides configuration parsing, invocation identity, artifact storage,
provider contracts, lifecycle coordination, PTF-log routing, manifests,
integrity checks, diagnostic-error recording, and runner reconciliation.

MS-SMBD is the first integrated consumer. Its code under
`TestSuites/MS-SMBD/src/Diagnostics/` maps suite properties, reads the
independent SUT `Platform` and Driver `DriverPlatform`, and composes the
provider appropriate for the actual Driver runtime. The current concrete
provider is Windows `NetshTrace`; Linux Driver topologies report
`ProviderUnsupported` until a specific Linux capture tool is qualified and a
provider is implemented.

Do not copy the shared implementation into another suite. Add a suite-specific
property map and thin lifecycle composition instead. The fixture at
`TestSuites/FileServer/src/Common/Diagnostics.Portability.Tests/` demonstrates
alternate property names, disabled zero-side-effect behavior, startup-error
recording, and explicit no-evidence finalization without an MS-SMBD
dependency.

The active MS-SMBD integration keeps one authored diagnostics policy surface:
`MS-SMBD_ServerTestSuite.ptfconfig`. Its deployment PTF owns topology facts
and does not duplicate `Diagnostics.*` values. Per-test outputs are
`ptf-log.ndjson`, `manifest.json`, and `capture.etl` when usable capture
succeeds; runner reconciliation writes `runner/runner-evidence.json`.
Diagnostics regression tests are supporting infrastructure tests, not protocol
conformance cases.
**Hardware-free SMBD review regressions:** `TestSuites\MS-SMBD\tests\Smbd.UnitTests.csproj` exercises the actual
adapter/test-suite assemblies and linked detector source, without connecting to a provider. Run from the repository root:
`dotnet test TestSuites\MS-SMBD\tests\Smbd.UnitTests.csproj -p:OS=Unix`.
On Windows, this deliberately selects the managed Linux conditional paths; it does **not** validate native compilation
or live Linux/Windows RDMA interoperability. The project links the detector's source and platform adapter to avoid pulling
in the plugin's UI/PowerShell dependencies. Its fake PTF checker rejects unsupported assertion operations.
The fixture sets `Diagnostics.Enabled=false` and `SutLog.Enabled=false` only in its synthetic configuration,
preventing capture or remote SUT log collection without changing the deployed suite's diagnostics policy.

Reuse `SmbdAdapter.GetRdmaChannelDataSize()` for the configured multiple-buffer-descriptor scenario: it caps
`RdmaChannelDataSizeInByte` at both SMB2 negotiated READ/WRITE limits and SMBD MaxReadWriteSize.
Other boundary tests retain their scenario-specific lengths. `QueryNetworkInterfaceMaxOutputResponse` controls the actual
IOCTL output request, capped at SMB2 MaxTransactSize with matching SMB2 credit charge (not SMBD credits).
`Smb2OverSmbdTestClient.Smb2QueryNetworkInterfaceInfo` has a raw-response overload
returning both buffers, `Packet_Header` and `IOCTL_Response` for format assertions.
The parsed overload delegates to it. Reuse this path for positive raw queries:
it reserves credits before selecting the MessageId and accounts exactly once;
do not call the one-credit binding-negative `AfterRawResponse` afterward.
The multi-channel scenario creates its own main-channel client; its initializer must forward this setting explicitly.
Its independent alternative-channel client must likewise receive `ClientMaxReadWriteSize` before negotiation.
`Smb2MultiChannelOverRdma.ReadFileFromAlternativeChannel` is the actual post-session-setup READ loop: both registered
memory lengths and encoded READ lengths use the smaller of effective SMBD MaxReadWriteSize and SMB2 MaxReadSize,
with a bounded tail. Its hardware-free regressions execute that loop and the real packet builder, replacing only provider
operations and negotiated state. Do not infer successful live negotiation or registration from those regressions.
`SmbdCreditManagement.ValidateReadResponse` must validate the last-credit grant on **every** received message before
final/empty exits or replenishment: the SDK already decremented client ReceiveCredits, which tracks the peer's remaining
SendCredits. A zero grant is legal when credits remain; there is no final/empty exception when they reach zero.
These invariants are covered by `ValidateReadResponse_ChecksEveryMessageBeforeReplenishment`,
`AlternativeChannelInitialization_ForwardsConfiguredCap`, and
`AlternativeChannelRead_BoundsActualRegisteredAndEncodedLengths` in the existing regression fixture.
The receive-overflow-disconnection test requires explicit `ExpectDisconnectOnReceiveOverflow=true` for an independently
verified provider contract; it is not a generic [MS-SMBD] 3.1.5.8 requirement and defaults to inconclusive.

`TestSuites\Common\Diagnostics.Ptf` supplies `PtfDiagnosticsSuite`, `PtfTestDiagnostics`, PTF log/lifecycle bridges and optional `SutLogCollector`. Provider selection uses DriverPlatform plus runtime, independently of SUT Platform. Other property namespaces use an explicit property map.

MS-SMBD integrates the bridge in `TestSuites\MS-SMBD\src\TestSuite\SmbdTestBase.cs`. Deployment owns topology; `MS-SMBD_ServerTestSuite.ptfconfig` owns Diagnostics.* policy. Per-invocation outputs are ptf-log.ndjson, manifest.json and capture.etl when capture succeeds; the runner reconciles authoritative TRX outcomes in runner\runner-evidence.json. Diagnostics.Enabled and SutLog.Enabled are disabled by default.

The runner starts its child once and preserves its exit code despite bootstrap/output/flush/append or warning-channel I/O failure. A failed output sink is discarded while both pipes continue draining. Unavailable fallback result storage omits optional TRX arguments rather than preventing launch. `RunnerExecutableTests` exercises real passing/failing test children plus a verbose synthetic child; `RunnerEvidenceStorage` is the narrow internal fault-injection seam. These tests do not qualify live capture or remote SUT logging.

For generated model cleanup, `FileServerPtfTestClassBase.BaseTestCleanup` wraps the actual PTF dispatcher in a `finally`; trailing `CleanupTestManager` alone is not a lifetime guarantee. The wrapper disposes diagnostics even if acquisition/unsubscribe/reset throws, records whether manager cleanup completed and does not replace the original exception. Executable fixtures in `FileServer\src\Diagnostics.Tests` verify actual PTF 2.7.0/MSTest 3.9.1 dispatch once, before class cleanup. A setup or protocol failure can coexist with successful cleanup.

`Mlx5SnifferCaptureProvider` reserves adapter ownership before native preflight/start and admits reuse only after the previous writer is stopped. Proven failed starts release the reservation; interrupted native starts without proven ownership retain admission and unresolved-writer evidence, not stop authority. Unresolved owned stops remain retryable and block reuse. Replaced handles cannot stop the new writer, and each confirmed start has its own duration enforcement. Reuse/failure/duration regressions use the controlled process executor, not live tooling.

An interrupted netsh start is resolved only by explicit no-session evidence or cleanup of the status-proven named session and exact output path. Failed, denied, foreign or unparseable recovery status remains unresolved without stopping an unproven session. Both Windows providers mark a duration-limited capture as incomplete collection even when its closed artifact finalizes successfully; normal cleanup remains complete. Native tool/status dialects and actual payload visibility still require separate live qualification.

`DiagnosticsInvocationLifecycle` restores the complete error ledger into the manifest, including the original protocol primary and sequence/timestamps. `AuxiliaryCaptureProvider` treats an unavailable auxiliary as optional, not a started writer as optional: unresolved, throwing or pending auxiliary stop must still attempt primary cleanup and retain failure/unresolved-writer evidence. Both stops are initiated independently; the orchestrator bounds their combined wait. Managed regressions in `Diagnostics.Tests\Lifecycle` and `Diagnostics.Tests\Providers` exercise these persistence and composite-ownership boundaries without a SUT.

Partial auxiliary starts retain their handles for cleanup; an indeterminate start without a handle remains unresolved and never authorizes stopping an unowned session. `CaptureProviderStartResult.Unresolved` expresses this distinction. Finalized artifacts and complete collection are separate: providers can return `Finalized(..., collectionComplete: false)`, propagated through orchestration and composite providers to a `Partial` manifest collection with `CollectionGap`, without inventing a protocol failure. These are diagnostics evidence policies, not SMB wire requirements.

---

## BranchCache Test Suite

**Path:** `TestSuites/BranchCache/src/`
**Solution:** `BranchCache.sln`
**Protocols tested:** MS-PCCRTP, MS-PCCRR, MS-PCHC, MS-PCCRC

---

## ADFamily Test Suite

**Path:** `TestSuites/ADFamily/src/`
**Solution:** `AD_Server.sln`
**Protocols tested:** MS-ADA1, MS-ADA2, MS-ADA3, MS-ADLS, MS-ADSC, MS-ADTS, MS-APDS, MS-DRSR, MS-FRS2, MS-LSAD, MS-LSAT, MS-SAMR, MS-NRPC

The largest test suite in the repo. Has C++ native components for some AD protocol operations. Contains many sub-directories under `TestSuite/` corresponding to each protocol.

---

## MS-WSP Test Suite

**Path:** `TestSuites/MS-WSP/src/`
**Solution:** `MS-WSP_Server.sln`
**Protocols tested:** MS-WSP (Windows Search Protocol)

---

## MS-XCA Test Suite

**Path:** `TestSuites/MS-XCA/src/`
**Solution:** `MS-XCA.sln`
**Protocols tested:** MS-XCA (Xpress Compression Algorithm)

This is a pure algorithm test suite — it does not require a network SUT. Tests run the compression/decompression algorithms against known test vectors.

---

## MS-ADFSPIP, MS-AZOD, MS-ADOD Test Suites

These smaller suites follow the same pattern but target specific AD-related protocols. Each has `src/Adapter/`, `src/TestSuite/`, and deployment scripts.

---

## How a Test Case Is Structured

### Lifecycle

```csharp
[TestClass]
public class Negotiation : SMB2TestBase
{
    private Smb2FunctionalClient client;

    [ClassInitialize()]
    public static void ClassInitialize(TestContext testContext)
    {
        TestClassBase.Initialize(testContext);     // PTF initialization
    }

    [ClassCleanup()]
    public static void ClassCleanup()
    {
        TestClassBase.Cleanup();
    }

    protected override void TestInitialize()
    {
        base.TestInitialize();                    // sets up testConfig, adapters
        client = new Smb2FunctionalClient(TestConfig.Timeout, TestConfig, BaseTestSite);
        client.ConnectToServer(TestConfig.UnderlyingTransport,
                               TestConfig.SutComputerName,
                               TestConfig.SutIPAddress);
    }

    protected override void TestCleanup()
    {
        client.Disconnect();
        base.TestCleanup();
    }

    [TestMethod]
    [TestCategory(TestCategories.Bvt)]
    [TestCategory(TestCategories.Smb21)]
    [TestCategory(TestCategories.Negotiate)]
    [Description("Verify server handles NEGOTIATE with SMB2 wildcard dialect")]
    public void BVT_Negotiate_Compatible_Wildcard()
    {
        BaseTestSite.Log.Add(LogEntryKind.TestStep, "Send negotiate with wildcard");
        uint status = client.MultiProtocolNegotiate(
            new[] { "SMB 2.002", "SMB 2.???" },
            (header, response) => {
                BaseTestSite.Assert.AreEqual(DialectRevision.Smb2Wildcard,
                                             response.DialectRevision,
                                             "Expected wildcard dialect");
            });
    }
}
```

### Test Categories

Test methods use `[TestCategory]` attributes to classify them. Common categories (defined in `TestCategories.cs`):
- `Bvt` — Basic Verification Test; smoke test, always run
- `Smb2002`, `Smb21`, `Smb30`, `Smb302`, `Smb311` — dialect-specific
- `Negotiate`, `Signing`, `Encryption`, `DurableHandle`, etc. — feature area
- `NonSmb` — tests that exercise authentication or transport but not SMB directly

The `.PLAYLIST` files in some suites (Kerberos) define curated sets of tests for specific configurations.

### Logging

Use `BaseTestSite.Log.Add(LogEntryKind.TestStep, "message")` for structured test step logging. Available kinds: `TestStep`, `Checkpoint`, `Comment`, `Debug`, `Warning`, `CheckFailed`, `CheckSucceeded`.

Assertions use `BaseTestSite.Assert.*` (not `Assert.*` directly) so that assertion failures are captured by PTF and appear in the test log with context.

### Adapters

Adapters are retrieved from the test site:
```csharp
var adapter = BaseTestSite.GetAdapter<ISutProtocolControlAdapter>();
```

Adapter implementations are specified in `.ptfconfig`:
```xml
<Adapters>
  <Adapter xsi:type="powershell" name="ISutCommonControlAdapter" scriptdir=".\SutCommonControlAdapter" />
  <Adapter xsi:type="managed"   name="ISutProtocolControlAdapter"
           adaptertype="Microsoft.Protocols.TestSuites.FileSharing.Common.Adapter.SutProtocolControlAdapter" />
</Adapters>
```

Type `powershell` — PTF auto-generates an adapter that delegates each method to a PowerShell script with the same name as the method.
Type `managed` — PTF instantiates the named C# class.

---

## How to Add a New Test Case

### 1. Find the right test class

Navigate to the protocol area: e.g., for a new SMB2 encryption test, go to `TestSuites/FileServer/src/SMB2/TestSuite/Encryption/`.

If a class already exists for that feature, add your method there. Otherwise, create a new class file.

### 2. Write the test method

```csharp
[TestMethod]
[TestCategory(TestCategories.Smb311)]
[TestCategory(TestCategories.Encryption)]
[Description("Verify server rejects unencrypted traffic on an encryption-required share.")]
public void Encryption_RejectUnencryptedAccess()
{
    // Arrange
    BaseTestSite.Log.Add(LogEntryKind.TestStep, "Connect to encryption-required share without encryption.");

    // Act & Assert
    uint status = client.TreeConnect(
        TestConfig.EncryptionRequiredShare,
        out uint treeId,
        checker: (header, response) => {
            BaseTestSite.Assert.AreNotEqual((uint)Smb2Status.STATUS_SUCCESS, header.Status,
                "Server should reject unencrypted access to encryption-required share.");
        });
}
```

### 3. Update documentation

Per `CONTRIBUTING.md`: if adding a new test case, update the corresponding **Test Design Specification** (found in `TestSuites/<Suite>/docs/`).

### 4. Add to ptfconfig if new config properties needed

Add new `<Property>` elements to `<Suite>.ptfconfig` and parse them in the relevant `TestConfig` class.

### 5. Build and run

```powershell
cd TestSuites/FileServer/src
./build.ps1
```

Then run from the output `drop/TestSuites/FileServer/Bin/` directory using vstest or PTM.
