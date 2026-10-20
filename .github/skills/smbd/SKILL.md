---
name: smbd
description: MS-SMBD / SMB Direct server test-suite guidance for RDMA transport, negotiation, credit and data-transfer tests. Use for TestSuites/MS-SMBD, SMB over RDMA, RoCE or iWARP; verify the current checkout and published specification before attributing a failure.
license: MIT
metadata:
  author: Microsoft
  version: "1.1"
---

# MS-SMBD test suite skill

## Classify and locate existing components

Load the [FileServer skill](../file-server/SKILL.md) first. SMB Direct transport behavior belongs in
`TestSuites/MS-SMBD`; file-system information semantics still require FSA domain classification.
SMB2 behavior over RDMA also needs the applicable MS-SMB2 requirements.

| Component | Repository path |
|---|---|
| Solution and build entry point | `TestSuites/MS-SMBD/src/MS-SMBD_Server.sln`, `TestSuites/MS-SMBD/src/build.ps1` |
| Transport and SMB2-over-SMBD tests | `TestSuites/MS-SMBD/src/TestSuite/SMBD`, `TestSuites/MS-SMBD/src/TestSuite/SMB2overSMBD` |
| Shared test setup | `TestSuites/MS-SMBD/src/TestSuite/SmbdTestBase.cs`, `Smb2OverSmbdTestBase.cs` in the same directory |
| Adapter and configuration | `TestSuites/MS-SMBD/src/Adapter/SmbdAdapter.cs`, `TestConfig.cs` in the same directory |
| SMB2-over-SMBD client | `TestSuites/MS-SMBD/src/Adapter/Smb2OverSmbdTestClient.cs` |
| Wire structures and client | `ProtoSDK/MS-SMBD/SmbdMessages.cs`, `ProtoSDK/MS-SMBD/SmbdClient.cs` |
| Setup and scenario guidance | `TestSuites/MS-SMBD/docs/MS-SMBD_ServerUserGuide.md`, `MS-SMBD_ServerTestDesignSpecification.md` in the same directory |

Verify paths and APIs in the checkout being tested. Diagnostics implementations and helper scripts from
another branch are not prerequisites or evidence that those capabilities exist here.

## Build and run

1. Read the User Guide prerequisites and `src/build.ps1`: this suite includes native RDMA dependencies,
   so a managed-only build is not a substitute for the solution build.
2. From `TestSuites\MS-SMBD\src`, use `.\build.ps1 -Configuration Debug`.
   Use a task-owned output directory if overriding `OutDir`; the build script clears that directory.
3. Configure the generated deployment/runtime ptfconfig copies for the authorized SUT, transport and
   driver. Read `Adapter/TestConfig.cs` and property descriptions before changing a setting.
   Do not commit credentials or machine-local configuration.
4. From the generated `drop\TestSuites\MS-SMBD\Batch` directory, list a bounded selection with
   `.\RunTestCasesByFilter.ps1 -Filter "Name=<TestMethod>" -DryRun`, then omit `-DryRun` to execute.
   Record discovery separately from execution. An RDMA-capable driver/SUT topology must actually be available.

## Specification and evidence

- Apply the FileServer skill's specification-validation workflow. Inspect the published MS-SMBD revision,
  relevant errata and exact sections; consult MS-SMB2 when validating upper-layer requests.
- Compare the test, adapter and SDK encoding with the wire requirement. Record MUST/SHOULD/MAY and
  applicability separately from product behavior; a Windows control run does not establish normative truth.
- Use the [test-debugging skill](../test-debugging/SKILL.md) to correlate TRX failures, packet evidence and
  available SUT logs. Missing evidence is a limitation, not proof of a SUT defect.
- Decode the actual capture encapsulation and header lengths rather than fixed Ethernet/IP/RDMA offsets.
  Interpret `DataOffset` and `DataLength` with bounds checks using the applicable wire definition.
  Do not assume every SMB Direct message carries an SMB2 payload.
- Check optional-feature negotiation before a feature-specific test. An unsupported optional feature does
  not excuse failure of an unrelated mandatory requirement.
- Never turn a timeout/exception into a pass or weaken an assertion solely to make an implementation pass.
  Record an unavailable prerequisite distinctly from a protocol failure.

## Changes and review

Keep fixes within the evidenced source/specification boundary. Explain non-obvious protocol decisions at
the change site; preserve accurate existing test annotations without claiming unexecuted conformance.
Rebuild and execute the affected cases in the required environment; report unavailable live boundaries.
Update the Test Design Specification and User Guide when their documented behavior changes.
Keep historical run reports and implementation-specific defect claims out of reusable skill guidance.
