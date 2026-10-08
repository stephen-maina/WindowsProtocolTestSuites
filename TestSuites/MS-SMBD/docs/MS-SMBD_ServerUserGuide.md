# MS-SMBD Server Test Suite User Guide

## Contents

* [Introduction](#introduction)
* [License Information](#license-information)
* [Further Assistance](#further-assistance)
* [Quick Start Checklist](#quick-start-checklist)
* [How Do I?](#how-do-i)
* [Requirements](#requirements)
    * [Network Infrastructure](#network-infrastructure)
    * [Environment](#environment)
    * [Driver Computer](#driver-computer)
    * [System Under Test (SUT)](#system-under-test-sut)
    * [Software](#software)
* [Network Setup](#network-setup)
    * [Network Environment](#network-environment)
    * [Verify Connectivity](#verify-connectivity)
      * [Verify Connectivity on Windows Client](#verify-connectivity-on-windows-client)
      * [Verify Connectivity on Linux Client](#verify-connectivity-on-linux-client)
* [Computer Setup](#computer-setup)
    * [Setup the Driver Computer](#setup-the-driver-computer)
    * [Setup the SUT](#setup-the-sut)
    * [Installed Files and Folders](#installed-files-and-folders)
* [Configuration](#configuration)
    * [Configuring the Test Suite](#configuring-the-test-suite)
        * [Required Configuration Settings](#required-configuration-settings)
        * [Configure Automated Per-Test Diagnostics](#configure-automated-per-test-diagnostics)
* [Running Test Cases](#running-test-cases)
    * [Prerequisite of Linux Client Environment](#prerequisite-of-linux-client-environment)
    * [Run the BVT Test Cases](#run-the-bvt-test-cases)
    * [Run All Test Cases](#run-all-test-cases)
    * [Check the Test Results](#check-the-test-results)
        * [Review the Log Files](#review-the-log-files)
        * [Manage the Generation of Log Files](#manage-the-generation-of-log-files)
* [Debugging Test Cases](#debugging-test-cases)
* [Capturing RDMA Traffic](#capturing-rdma-traffic)
* [Tested RDMA Adapter](#tested-rdma-adapter)

## Introduction

This user guide provides information about how to install, configure, and run the MS-SMBD Test Suite in a test environment. This suite is designed to test the implementations of MS-SMBD protocol, as specified in the Microsoft document _[MS-SMBD]._ This user guide provides information about using this test suite on the Microsoft® Windows® operating system and on operating systems that are not Windows based. 

This test suite only tests the protocol implementation behaviors which can be observed on the wire. For detailed information about the design of this test suite, see [MS-SMBD_ServerTestDesignSpecification](MS-SMBD_ServerTestDesignSpecification.md ).

## License Information

For the licensing information, see the End User License Agreement (EULA) that was provided with this test suite. The EULA is EULA.rtf file in the installation folder.

## Further Assistance

If you need further information about this test suite or need assistance in troubleshooting the issues related to this test suite, contact dochelp@microsoft.com.

## Quick Start Checklist

The following checklist shows the tasks you need to complete in order to set up the test suite and run the test cases. 

![image2.png](./image/MS-SMBD_ServerUserGuide/image2.png)
Note 

>For the workgroup environment, skip the tasks that are related to setting up and configuring the domain controllers.

|  **Check**|  **Task**|  **Topic**| 
| -------------| -------------| ------------- |
| □| Download the test suite for the protocol implementation.| See [Installed Files and Folders](#installed-files-and-folders) for a list of the files in the download package.| 
| □| Confirm that your test environment meets the requirements of the test suite.| See [Requirements](#requirements).| 
| □| Install the required software.| See [Software](#software) for the information about software required for installing the test suite.| 
| □| Set up the driver computer| See [Setup the Driver Computer](#setup-the-driver-computer).| 
| □| Set up the system under test (SUT) | See [Setup the SUT](#setup-the-sut).| 
| □| Set up the network| See [Network Setup](#network-setup).| 
| □| Verify the connection between the driver computer, the SUT and other computers.| See [Verify Connectivity](#verify-connectivity).| 
| □| Configure the test suite.| See [Configuring the Test Suite](#configuring-the-test-suite).| 

## How Do I?

Use the following quick reference to learn how to complete common tasks.

|  **How do I…?**|  **For more information…**| 
| -------------| ------------- |
| Set up the test environment| [Network Setup](#network-setup) and [Computer Setup](#computer-setup)| 
| Verify the connection from the driver computer to other computers in the test environment| [Verify Connectivity](#verify-connectivity)| 
| Setup a SUT| [Setup the SUT](#setup-the-sut)| 
| Configure the test suite settings| [Configuring the Test Suite](#configuring-the-test-suite)| 
| Collect a per-test trace and immutable PTF log| [Configure Automated Per-Test Diagnostics](#configure-automated-per-test-diagnostics)|
| Run a BVT test| [Run the BVT Test](#run-the-bvt-test-cases)| 
| Run test cases| [Run All Test Cases](#run-all-test-cases) | 
| Debug test cases| [Debugging Test Cases](#debugging-test-cases)| 
| Get the results of test runs| [Check Test Results](#check-the-test-results)| 

## Requirements

This section describes the requirements for the test environment that are used to run this test suite.

![image2.png](./image/MS-SMBD_ServerUserGuide/image2.png)
Note 

>The requirements in this section apply to Windows-based computers in the test environment. The driver computer can use a supported Windows operating system or Ubuntu 24.04 LTS. Automated per-test capture currently has a concrete backend only when the driver computer runs Windows. Linux driver computers can run the protocol tests, but diagnostics capture reports `ProviderUnsupported` until a Linux capture tool is qualified and a provider is implemented.

### Network Infrastructure

* A test network is required to connect the test computer systems

* It must consist of an isolated hub or switch

* It must not be connected to a production network or used for any other business or personal communications or operations

* It must not be connected to the internet 

* IP addresses must be assigned for a test network

* Computer names should be assigned in a test network infrastructure

* User credentials used on the system must be dedicated to the test network infrastructure

* Details including computer IP addresses, names and credentials are saved in log files

* Refer to the Detailed Logging Support section 

Refer to the Privacy Statement and EULA for further information

[Please refer to the Tested RDMA Adapter](#tested-rdma-adapter)

### Environment

Run this test suite in a domain or non-domain environment that contains the following computers (physical or virtual): 

* A driver computer running Microsoft® Windows Server® 2022 or later versions. For RDMA testing scenarios, a Linux-based operating system (e.g., Ubuntu 24.04) can also be used.

* A system under test running Microsoft® Windows Server® 2022 or later versions

### Driver Computer

The minimum requirements for the driver computer are as follows. 

|  **Requirement**|  **Description**| 
| -------------| ------------- |
| Operating system| Microsoft® Windows Server 2022 (version 21H2), Microsoft® Windows Server 2025 (version 24H2), Standard Edition or later versions; Ubuntu 24.04| 
| Feature| An RDMA capable NIC is installed and ready to use| 
| Memory| 16 GB RAM| 
| Disk space| 60 GB | 

Note:
For RDMA testing scenarios, the driver computer can also run a Linux-based
operating system (for example, Ubuntu 24.04.x) with an RDMA-capable NIC installed.

### System Under Test (SUT)

The minimum requirements for the SUT are as follows.

|  **Requirement**|  **Description**| 
| -------------| ------------- |
| Operating system| Microsoft® Windows Server 2022 (version 21H2), Microsoft® Windows Server 2025 (version 24H2), Standard Edition or later versions, or a SUT implementation that is not based on the Windows operating system| 
| Feature| An RDMA capable NIC is installed and ready to use| 
| Memory| 16 GB RAM| 
| Disk space| 60 GB| 

### Software

All of the following software must be installed on the driver computer before installing the test suite. 

**Required Software**

All common softwares listed in [prerequisites](https://github.com/microsoft/WindowsProtocolTestSuites#prerequisites) for running Windows Protocol Test Suites.

* **Windows PowerShell**

    **Windows PowerShell** is required.

**Optional Software**

* **Protocol Test Manager**

    **Protocol Test Manager** provides a graphical user interface (UI) to facilitate configuration and execution of Microsoft® Windows Protocol Test Suite tests. Its use is highly recommended.

* **Microsoft® Message Analyzer**

    **Microsoft® Message Analyzer** (MMA) is listed here as an optional tool because the test cases of themselves neither perform live captures or capture verifications during execution. However, MMA can be helpful with debugging test case results, by analyzing ETL files that are generated by the Test Cases, that is, if you enable the the Automatic Network Capturing feature in the Protocol Test Manager (PTM) during test case configuration. The Automatic Network Capturing feature is further described in the [PTF User Guide](https://github.com/Microsoft/ProtocolTestFramework/blob/main/docs/PTFUserGuide.md#-automatic-network-capturing).

    ![image2.png](./image/MS-SMBD_ServerUserGuide/image2.png)Note

    November 25 2019 - Microsoft Message Analyzer (MMA) has been retired and removed from public-facing sites on microsoft.com. A private MMA build is available for testing purposes; to request it, send an email to [getmma@microsoft.com](mailto:getmma@microsoft.com).

## Network Setup

Run this test suite in a domain or a non-domain environment using either physical or virtual machines. This section is about the non-domain test environment using physical machines. 

For information about configuring a virtual machine, see [https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/create-virtual-machine](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/create-virtual-machine). The configuration of virtual machines for this test suite is not covered in this user guide. 

#### Network Environment

The domain environment requires interactions between the following computers and servers. 

* The driver computer runs the test cases by sending requests over the wire in the form of protocol messages. 

* The SUT runs an implementation of the protocol that is being tested. The SUT responds to the requests that the driver computer sends.

The following figure shows the domain environment with recommended network configurations for your reference.

![image4.png](./image/MS-SMBD_ServerUserGuide/image4.png)

| |  | |   |
| -------------| -------------| -------------| ------------- |
| Machine Name/Access Point| NIC Type| IPv4| Subnet Mask| 
| SMBD-Client01| NIC| 192.168.1.111| 255.255.255.0| 
| | RDMA-NIC| 192.168.1.11| 255.255.255.0| 
| SMBD-SUT01| NIC| 192.168.1.112| 255.255.255.0| 
| | RDMA-NIC| 192.168.1.12| 255.255.255.0| 

For RDMA-based testing, assign static IP addresses to the RDMA NICs on both
the driver computer and the SUT. Ensure the RDMA NICs are directly connected
and reachable before proceeding with test suite configuration.

#### Verify Connectivity

After you set up the environment, verify the connection between the driver computer and the SUT over both the NIC and the RDMA-NIC. You can use the following steps to check the connectivity between the two Windows-based computers. For further information about other operating systems, see the administration guide for your operating system.

To check the connection from the driver computer

![image2.png](./image/MS-SMBD_ServerUserGuide/image2.png)
Note 

>Do not proceed with the configuration of the test suite until connectivity is confirmed. Any issue with the network connectivity must be resolved before configuring the test suite.

##### Verify Connectivity on Windows Client
* Disable active firewalls in the test environment.

* Open Windows PowerShell.

* **Ping** the IP address of the NIC.

* **Ping** the IP address of the RDMA-NIC.

* Check the status of RDMA NIC.
   ```bash
   Get-NetAdapterRdma
   ```
Confirm that the 'Enabled' is 'True', 'Operational' is 'True'.

##### Verify Connectivity on Linux Client

* Verify RDMA port state

   Check the RDMA port status:

   ```bash
   ibv_devinfo
   ```

   Confirm that the RDMA port state is `ACTIVE`.

## Computer Setup

This section explains how to set up the computers for the test environment.

![image2.png](./image/MS-SMBD_ServerUserGuide/image2.png)
Note 

>For the workgroup environments, skip the tasks that are related to setting up and configuring the domain controllers.

### Setup the Driver Computer

This section describes how to set up the driver computer.

![image5.png](./image/MS-SMBD_ServerUserGuide/image5.png)
Important 

>Microsoft Visual Studio 2019 must be installed on the driver computer before you run the test suite installer.

To set up the Windows driver computer

* Install the required and the optional software as mentioned in [6.5](#software).
* Install <a href="https://www.microsoft.com/en-us/download/details.aspx?id=36043">Network Direct DDK.
* Install Windows 10 SDK (10.0.19041.0)
* Install C++ 2019 Redistributable Update
* Install the related R-NIC Driver.

To set up the Linux driver computer

* Install **Ubuntu 24.04**.
* Install **NVIDIA DOCA 3.3.0** for Mellanox RDMA NICs following the official NVIDIA documentation.
* Disable **Secure Boot** in the BIOS to avoid driver signing and kernel module loading issues.
* Disable the firewall to prevent interference with RDMA traffic.
* Navigate to `TestSuites/MS-SMBD/Setup/Scripts` in the WindowsProtocolTestSuites repository
  and execute the setup script on the driver computer.

### Setup the SUT

To set up the SUT

* Install related R-NIC Driver.

* Create local or domain user account.

* Create an SMB2 share folder.

* Create a file with arbitrary content under the SMB2 share folder, and make sure its file size is at least the `MaxWriteSize` supported by the SMB2 implementation of SUT.

### Installed Files and Folders

The test suite is installed in folder <TestSuiteLocation>\\MS-SMBD\\Server-Endpoint\\ _< version #  >_ \\.

![image2.png](./image/MS-SMBD_ServerUserGuide/image2.png)
Note 

>The  < _version #  >_  placeholder indicates the installed build of the test suite.

|  **File or Folder**|  **Description**| 
| -------------| ------------- |
| Batch| The command files which you can use to run individual test case or all the test cases.| 
| Bin| The test suite binaries and the configuration files.| 
| Docs| **[MS-SMBD].pdf** – The technical document that this test suite is based on.| 
| | **MS-SMBD_ServerUserGuide.md** – A user guide about deploying the test environment and running the test cases.| 
| | **MS-SMBD_ServerTestDesignSpecification.md** – An overview document about the test environment and the test scenario design.| 
| | **ReleaseNotes.txt** – An overview of recent releases.| 
| EULA.rtf| The End User License Agreement.| 


## Configuration

This section explains how to configure the test environment.

### Configuring the Test Suite

This test suite is installed with default settings. You may need to change these settings if you use a customized test environment or you would like to customize your test runs. 

To change environment settings, edit the MS-SMBD_ServerTestSuite.deployment.ptfconfig file in the directory <TestSuiteLocation>\\MS-SMBD\\Server-Endpoint\\ _< version #  >_ \\Bin.

The suite intentionally separates configuration ownership:

* `MS-SMBD_ServerTestSuite.deployment.ptfconfig` describes environment facts,
  including the SUT `Platform`, the test-driver `DriverPlatform`, host names,
  and RDMA interface addresses.
* `MS-SMBD_ServerTestSuite.ptfconfig` is the single authored diagnostics-policy
  layer. Configure every `Diagnostics.*` property in this file rather than
  duplicating diagnostics values in the deployment file.

#### Required Configuration Settings

The following table describes the most common configuration properties and
their values. These properties are required to run the tests. Update
environment and topology values in
`MS-SMBD_ServerTestSuite.deployment.ptfconfig`; update suite policy, including
all `Diagnostics.*` values, in `MS-SMBD_ServerTestSuite.ptfconfig`. Both files
are in `<TestSuiteLocation>\MS-SMBD\Server-Endpoint\<version>\Bin`.

* **SUT Settings.**

| |   |
| -------------| ------------- |
|  **Property**|  **Description**| 
| Platform| The operating system family of the SUT. Use `NonWindows` for a supported Linux SUT, or the applicable supported Windows platform value listed in the deployment configuration.| 
| DriverPlatform| The operating system family of the computer that runs the test process. Use `NonWindows` for the supported Linux driver, or the applicable supported Windows platform value. Automated diagnostics verifies this value against the actual local runtime before selecting a capture provider.| 
| SutComputerName| The hostname of SUT.| 
| | The default value is “SMBD-SUT01”| 
| DomainName| The domain name of the test network environment. If it non-domain envrionment, use the SutComputerName as Domain Name.| 
| | The default value is “SMBD-SUT01”| 
| SutUserName| The username of the SUT administrator.| 
| | The default value is “administrator”.| 
| SutPassword| The password of the SUT administrator.| 
| | The default value is “Password01!”.| 
| ClientRNicIp| The IP address of the RDMA-NIC on the Driver computer.| 
| | The default value is “192.168.1.11”.| 
| ServerRNicIp| The IP address of the RDMA-NIC on the SUT.| 
| | The default value is “192.168.1.12”.| 
| ClientNonRNicIp| The IP address of the NIC on the Driver computer.| 
| | The default value is “192.168.1.111”.| 
| ServerNonRNicIp| The IP address of the NIC on the SUT.| 
| | The default value is “192.168.1.112”.| 
| SmbdTcpPort| The TCP port value for SMBD transport.| 
| | The default value is 445. | 
| ShareFolder| The share folder for testing on the SUT.| 
| | The default value is “SMBDTest”.| 
| TestFile_ReadLargeFile| The file name of a large file for the testing the reading file.| 
| | The default value is “testFile_ReadLargeFile.txt”| 
| SmallFileSizeInByte| The size in bytes of a small file.| 
| | The supported value for SmallFileSizeInByte is from 128 bytes to SMBD negotiated MaxSendSize (The default value of SMBD negotiated MaxSendSize is 1364 bytes).| 
| | The default value is 500.| 
| ModerateFileSizeInByte| The size in bytes of a moderate file.| 
| | The supported value for ModerateFileSizeInByte is from SMBD negotiated MaxSendSize (Default value of SMBD negotiated MaxSendSize is 1364 bytes) to SMBD negotiated MaxFragmentedSize (Default value of SMBD negotiated MaxFragmentedSize is 131072 bytes)| 
| | The default value is 65536.| 
| LargeFileSizeInKB| The size in KB of a large file. The size must be large enough for the test suite to transport large data over RDMA.| 
| | Supported value for LargeFileSizeInKB is from SMBD negotiated MaxFragmentedSize (Default value of SMBD negotiated MaxFragmentedSize is 128KB) to smaller of SMB2 negotiated MaxReadSize and MaxWriteSize (Windows Server 2012 without [MSKB-2934016] limits MaxReadWriteSize to 1048576 (1024KB). Otherwise, the limit is 8388608 (8192KB).)| 
| | The default value is 8192.| 
| Smb2ConnectionTimeoutInSeconds| The timeout value for SMB2 operation.| 
| | The default value is 125.| 
| SecurityPackageForSmb2UserAuthentication| The Security Package Type for SMB2 user authentication.| 
| | The supported value is "Negotiate", "Kerberos" or "Ntlm".| 
| | The default value is "Negotiate"| 
| NDVersion| The Network Direct Service Provider Interface (NDSPI) version used by the RDMA layer.| 
| |Must match the NDVersion the Smbd project (ProtoSDK\MS-SMBD\Smbd.csproj) was built with. <br> NDv1 - uses the wrapper defined in ProtoSDK\RDMA. <br> NDv2 - uses the wrapper defined in ProtoSDK\RDMANdv2| 
| | The default value is “NDv2”|


* **RDMA Capability Settings.**

| |   |
| -------------| ------------- |
|  **Property**|  **Description**| 
| InboundEntries| The maximum number of outstanding Receive requests for the RDMA-NIC driver.| 
| | The default value is 63.| 
| OutboundEntries| The maximum number of outstanding Send, SendAndInvalidate, Bind, Invalidate, Read, and Write requests for the RDMA-NIC driver.| 
| | The default value is 63.| 
| InboundReadLimit| The maximum inbound read limit for the RDMA-NIC driver.| 
| | The default value is 10.| 
| EndianOfBufferDescriptor| Endianness of BufferDescriptor returned from the RDMA-NIC driver. In MS-SMBD, all the messages MUST be transported as little-endian. If the buffer descriptor returned from the RDMA-NIC driver is big-endian, the buffer descriptor MUST be reversed to little-endian. | 
| | The supported value is "BigEndian" or "LittleEndian".| 
| | The default value is “BigEndian”.| 


* **MS-SMBD Capabilities Settings.**

The following settings are the capability of the MS-SMBD protocol.

| |   |
| -------------| ------------- |
|  **Property**|  **Description**| 
| ReceiveCreditMax| The maximum number of credits to grant to the SUT.| 
| | The defualt value is 255.| 
| SendCreditTarget| The initialized Send Credit target to be requested of the SUT.| 
| | The default value is 255.| 
| MaxSendSize| The initialized maximum single-message size in bytes which can be sent.| 
| | The default value is 1364.| 
| MaxFragmentedSize| The maximum fragmented upper-layer payload receive size in bytes.| 
| | The default value is 131072.| 
| MaxReceiveSize| The initialized maximum single-message size in bytes which can be received from the SUT.| 
| | The default value is 8192| 
| KeepAliveInterval| The interval in seconds to initiate send of a keepalive message from the SUT.| 
| | The default value is 120.| 
| DisconnectionTimeoutInSeconds| The timeout value in seconds that the test suite will wait for disconnection.| 
| | The default value is 1.| 


* **MS-SMBD Test Case Switches.**

| |   |
| -------------| ------------- |
|  **Property**|  **Description**| 
| CheckDataLengthRemainingDataLength| The switch which controls whether the SUT checks “The sum of the received DataOffset and DataLength fields are less than or equal to the length of the received message.”.| 
| | The defualt value is “false”.| 
| RdmaLayerLoggingEnabled| The switch controls whether verbose RDMA layer log is printed. Set to “true” to print the RDMA layer log, otherwise set to “false”.| 
| | The default value is “false”.| 

#### Configure Automated Per-Test Diagnostics

Automated diagnostics creates one evidence directory for each test invocation.
On a Windows driver computer, the suite uses the built-in
`C:\Windows\System32\netsh.exe` program and its `trace` command. There is no
separate `netshtrace` download. Starting physical packet capture normally
requires running Protocol Test Manager or the command-line test runner from an
elevated Administrator process.

Set `Platform` and `DriverPlatform` independently in
`MS-SMBD_ServerTestSuite.deployment.ptfconfig`:

| SUT `Platform` | Driver `DriverPlatform` | Current automated capture behavior |
|---|---|---|
| Windows value | Windows value | Uses the Windows `NetshTrace` provider. |
| `NonWindows` | Windows value | Uses the same Windows `NetshTrace` provider; the SUT operating system does not select the local capture backend. |
| Windows value | `NonWindows` | Valid test topology, but capture reports `ProviderUnsupported` because no Linux backend is qualified. |
| `NonWindows` | `NonWindows` | Valid test topology, but capture reports `ProviderUnsupported` because no Linux backend is qualified. |

`DriverPlatform` must agree with the operating system that is actually running
the test process. A missing, unknown, or mismatched value fails closed instead
of starting the wrong capture tool.

Configure diagnostics only in `MS-SMBD_ServerTestSuite.ptfconfig`. The following
example enables bounded Windows collection and places the per-test log beside
the trace:

```xml
<Property name="Diagnostics.Enabled" value="true" />
<Property name="Diagnostics.ArtifactRoot" value="C:\WPTS-Diagnostics" />
<Property name="Diagnostics.Capture.Provider" value="Automatic" />
<Property name="Diagnostics.Capture.ToolPath" value="" />
<Property name="Diagnostics.Capture.Targets" value="" />
<Property name="Diagnostics.Capture.TrafficScope" value="RdmaFocused" />
<Property name="Diagnostics.Capture.StartTimeout" value="00:00:30" />
<Property name="Diagnostics.Capture.StopTimeout" value="00:01:00" />
<Property name="Diagnostics.Capture.MaxDuration" value="00:05:00" />
<Property name="Diagnostics.Capture.MaxBytes" value="536870912" />
<Property name="Diagnostics.Capture.Format" value="Native" />
<Property name="Diagnostics.Logs.NativeEnabled" value="false" />
<Property name="Diagnostics.Retention" value="KeepAll" />
```

To collect diagnostics on a Windows driver:

1. In `MS-SMBD_ServerTestSuite.deployment.ptfconfig`, set `Platform` for the
   SUT and set `DriverPlatform` to the supported Windows value for the driver.
2. In `MS-SMBD_ServerTestSuite.ptfconfig`, set
   `Diagnostics.Enabled=true`, configure an absolute local
   `Diagnostics.ArtifactRoot`, and set the required time and byte bounds.
3. Leave `Diagnostics.Capture.ToolPath` empty to use the built-in
   `C:\Windows\System32\netsh.exe`. Leave `Diagnostics.Capture.Targets` empty
   to use `ClientRNicIp`, or provide one canonical IPv4 address.
4. Start Protocol Test Manager or the command-line runner as Administrator,
   then run the tests normally.
5. Inspect the invocation directory under `Diagnostics.ArtifactRoot`.
   `capture.etl`, when usable capture succeeds, and `ptf-log.ndjson` are
   written to the same directory automatically and recorded in
   `manifest.json`.

On a Linux driver, follow the same configuration ownership rules, set
`DriverPlatform=NonWindows`, and use a Linux absolute artifact root. The
protocol tests remain a valid topology, but automated capture currently
reports `ProviderUnsupported`; do not configure an unqualified capture tool.

| Property | Required behavior |
|---|---|
| `Diagnostics.Enabled` | Set to `true` to enable collection. Missing, empty, or `false` leaves diagnostics disabled and creates no diagnostics artifacts. |
| `Diagnostics.ArtifactRoot` | Absolute local path on the driver computer. Use a drive-qualified path on Windows, such as `C:\WPTS-Diagnostics`, or an absolute path on Linux, such as `/var/tmp/wpts-diagnostics`. UNC paths and relative paths are not accepted. |
| `Diagnostics.Capture.Provider` | Use `Automatic` for normal operation. On a Windows driver this selects `NetshTrace`. Explicit `NetshTrace` is also accepted on Windows. |
| `Diagnostics.Capture.ToolPath` | Leave empty to use the built-in Windows path. A Windows override must be an absolute `.exe` path. Do not configure a Linux tool path until that utility has been qualified for the target RDMA environment. |
| `Diagnostics.Capture.Targets` | Semicolon-separated unique selectors. The current `NetshTrace` provider requires exactly one canonical IPv4 address. When empty, the suite uses `ClientRNicIp` from the deployment configuration. |
| `Diagnostics.Capture.TrafficScope` | `RdmaFocused` or `Broader`. The value is recorded in evidence. The current Windows provider captures the selected physical IPv4 path; neither value by itself proves RDMA-only filtering or complete SMB Direct visibility. |
| `Diagnostics.Capture.StartTimeout` | Positive invariant `TimeSpan` in `c` format, for example `00:00:30`. |
| `Diagnostics.Capture.StopTimeout` | Positive invariant `TimeSpan` in `c` format, for example `00:01:00`. |
| `Diagnostics.Capture.MaxDuration` | Positive invariant `TimeSpan` safety bound. Reaching the bound stops the invocation-owned session and marks the capture partial. |
| `Diagnostics.Capture.MaxBytes` | Positive decimal byte limit. The Windows provider converts it to a whole-MiB `netsh` limit and rejects values below one MiB. |
| `Diagnostics.Capture.Format` | Only `Native` is currently supported. Windows output is ETL; it is not advertised as pcap or pcapng. |
| `Diagnostics.Logs.NativeEnabled` | Native/driver-log policy metadata. The immutable per-test `ptf-log.ndjson` is finalized regardless of this value. Setting this to `true` does not add or qualify a vendor-specific driver capture. |
| `Diagnostics.Retention` | Only `KeepAll` is currently supported. The suite does not automatically delete old evidence. |

Linux path parsing is supported, including case-sensitive containment and
extensionless tool paths. This path support does not mean that Linux packet
capture is supported. Do not assume that `tcpdump`, `dumpcap`, or another
utility can observe offloaded RDMA traffic; qualify the installed tool,
permissions, interfaces, ownership, stop behavior, loss statistics, and actual
RDMA/RoCE visibility first.

For a runner-managed invocation, evidence is organized beneath the configured
artifact root by run and test identity. The per-test invocation directory
contains:

```text
capture.etl
ptf-log.ndjson
manifest.json
```

`capture.etl` is present only when the Windows provider completes with a usable
capture. `ptf-log.ndjson` is written automatically to the same invocation
directory; there is no second log-directory property and no manual copy step.
The manifest records configuration provenance, artifact hashes, collection
status, cleanup state, and diagnostics errors. After the command-line runner
reconciles the test results, run-level evidence is written under
`runner\runner-evidence.json`.

The existing `MS-SMBD_Log.txt` and `MS-SMBD_Log.xml` files remain mutable,
suite-wide PTF outputs. They are not copied while active and should not be used
as substitutes for the invocation-scoped `ptf-log.ndjson`.

Diagnostics failure is recorded separately from the protocol-test outcome.
For example, an unsupported capture backend does not turn a passing protocol
test into a failure, and a valid trace does not turn a failing protocol test
into a pass.

**Troubleshooting**

| Symptom | Check |
|---|---|
| No diagnostics directory is created | Confirm `Diagnostics.Enabled` is `true` and every required timeout/limit value is present and valid. |
| `ProviderUnsupported` on a Linux driver | This is the current expected result; Linux path support exists, but no Linux capture backend is qualified. |
| `ProviderUnsupported` on a Windows driver | Confirm `DriverPlatform` is a supported Windows value and the test process is actually running on Windows. |
| Tool missing | Leave `Diagnostics.Capture.ToolPath` empty or verify that the configured absolute `.exe` exists. |
| Permission denied or capture start failure | Restart Protocol Test Manager or the command-line runner from an elevated Administrator process. |
| Target rejected | Use one canonical IPv4 address, or leave the property empty and correct `ClientRNicIp`. Do not use abbreviated IPv4, leading-zero IPv4, IPv6, interface names, or multiple selectors with the current Windows provider. |
| `manifest.json` reports no usable capture | Inspect its diagnostics errors. An ETL is registered only after targeted stop, writer closure, non-empty validation, and hashing succeed. |
| ETL exists but expected RDMA traffic is absent | Verify the selected client RDMA IPv4 address and the actual NIC/driver path. ETL existence alone does not prove RDMA/RoCE visibility or complete SMB Direct payload capture. |

Capture files and logs can contain file data, protocol payloads, host names, IP
addresses, and other sensitive environment information. Restrict access to the
artifact root, review evidence before sharing it, and follow the applicable
retention policy. Do not assume that a capture is free of credentials or
secrets merely because configuration values are sanitized in the manifest.

## Running Test Cases

This test suite includes command files that you can use to run some basic test cases. Each test case verifies the protocol implementation based on a given scenario. 

You can find these command files in the following directory: 
<TestSuiteLocation>\\MS-SMBD\\Server-Endpoint\\ _< version #  >_ \\Batch

You can run these command files either in the command prompt or by selecting and clicking in the File Explorer.

### Prerequisite of Linux Client Environment

On the Linux Driver computer, run the following command to build the test suite:

```bash
./build.sh
```

### Run the BVT Test Cases

This test suite contains a set of basic test cases called Basic Verification Test (BVT). These test cases perform basic functionality tests to evaluate the implementation on the SUT. Use the steps below to run all BVT test cases.

To run the BVT test cases 

Windows
```bash
.\RunTestCasesByFilter.ps1 -Filter "Category=BVT"
```

Linux
```bash
pwsh ./RunTestCasesByFilter.ps1 -Filter "Category=BVT"
```

### Run All Test Cases

Use the steps below to run all the test cases.

To run all the test cases 

Windows
```bash
.\RunAllTestCases.ps1
```

Linux
```bash
pwsh ./RunAllTestCases.ps1
```

### Check the Test Results

This section describes the review of log files and the management of their generation.

#### Review the Log Files

You can find the log files in the "TestResults" directory, a subdirectory of Batch folder in the test suite installation directory. The log files that contain test suite results use a  * .trx file name, in which the asterisk (" * ") character represents the user name, the protocol name, or both.

Additional log files are used for generating requirement coverage reports and diagnosing test issues. Their settings can be found in the  * .ptfconfig or  * .deployment.ptfconfig files. The file names, corresponding paths, and formats can be set in the Sinks node of the configuration file. 

The following instruction provides an example of how to cause log entries for the "Debug" logging sink not to be written into the MS-SMBD_Log.xml file in the current directory:
 < File id="XMLLog" directory=".\    estLog" file="MS-SMBD_Log.xml" format="xml"/ >  

When automated diagnostics is enabled, also inspect the test invocation's
`manifest.json`, `ptf-log.ndjson`, and, when capture succeeded, `capture.etl`
under `Diagnostics.ArtifactRoot`. For command-line runner executions,
`runner\runner-evidence.json` records authoritative test-result reconciliation.

#### Manage the Generation of Log Files

For further information about logging in the Protocol Test Framework (PTF), see the _PTF User Guide_ in the PTF installation directory

## Debugging Test Cases

You can open the Visual Studio Solution file (.sln) installed with this test suite to debug additional test cases that you create for your protocol implementation. 

![image2.png](./image/MS-SMBD_ServerUserGuide/image2.png)
Note 
Copy SM-SMBD_ServerTestSuite.deployment.ptfconfig from <TestSuiteLocation>\\MS-SMBD\\Server-Endpoint\\ < version #  > \\Bin to <TestSuiteLocation>\\MS-SMBD\\Server-Endpoint\\ < version #  > \\Source\\Server\\TestSuite and replace the original file

To debug a test case

* On the driver computer, use Microsoft® Visual Studio® to open the following solution file:
<TestSuiteLocation>\\MS-SMBD\\Server-Endpoint\\ _< version #  >_ \\Source\\Server\\TestCode\\MS-SMBD_Server.sln

* In Visual Studio, in the Solution Explorer window, right-click the **Solution ‘MS-SMBD_Server’**, and select **Build Solution**.

## Capturing RDMA Traffic

This section describes how to capture RDMA traffic when running the MS-SMBD
Server Test Suite, which can be helpful for troubleshooting and protocol
analysis in RDMA-based scenarios.

For automated per-test Windows collection, use
[Configure Automated Per-Test Diagnostics](#configure-automated-per-test-diagnostics).
The automated provider uses the built-in `netsh.exe`, owns a distinct named
session for each invocation, and writes `capture.etl` beside
`ptf-log.ndjson`.

The `Mlx5Cmd.exe` procedure below is a separate, manual NVIDIA/Mellanox
troubleshooting workflow. It is not selected by the automated diagnostics
configuration, and its existence does not qualify other NIC vendors or a Linux
capture backend.

> Note  
> RDMA traffic is typically offloaded to the network adapter and may not be
> visible through traditional packet capture tools. The steps below describe
> a vendor-provided method for capturing RDMA (RoCEv2) traffic on Windows
> systems using Mellanox adapters.

### Supported Environment

* Operating System: Windows Server 2019 / 2022 or later
* RDMA Adapter: Mellanox ConnectX‑4 / ConnectX‑5
* RDMA Driver: mlx5 (WinOF‑2)
* Capture Tool: Mlx5Cmd.exe
* Analysis Tool: Wireshark

### Prerequisites

Before capturing RDMA traffic, ensure that:

* RDMA connectivity between the Driver computer and the SUT has been verified.
* RDMA traffic is actively generated (for example, by running MS-SMBD test
  cases or other RDMA workloads).
* `Mlx5Cmd.exe` is available on the system and can be executed from
  PowerShell.

### Capture RDMA Traffic Using Mlx5Cmd

**Generate RDMA Traffic**

   Run some RDMA traffic.
   This can be done by running MS-SMBD test cases or any RDMA bandwidth test
   tool.

**Start Packet Capture**

   Open PowerShell and start the RDMA sniffer on the RDMA interface
   (for example, `RDMA1`):

```powershell
Mlx5Cmd.exe -Sniffer -name RDMA1 -start -filename smbd_rdma_capture.pcap
```

Where:

* `RDMA1` is the RDMA-capable network interface.
* `smbd_rdma_capture.pcap` is the output capture file.

**Stop Packet Capture**

After sufficient traffic has been generated, stop the capture:

```powershell
Mlx5Cmd.exe -Sniffer -name RDMA1 -stop
```

**Analyze the Capture**

Open the generated .pcap file using Wireshark.

For RoCEv2 traffic, the default UDP port is: UDP 4791

This filter can be used to identify RoCEv2 RDMA packets during analysis.

## Tested RDMA Adapter

Here we list the RDMA adapter we tested.

| Manufacturer | Model                    | Driver                                                                 | UserGuide                                                                 |
|--------------|--------------------------|------------------------------------------------------------------------|---------------------------------------------------------------------------|
| Chelsio      | T520-CR                  | [Windows](https://service.chelsio.com/downloads/Microsoft/): Unified Wirev6.16.17.0 <br> | [Windows](https://service.chelsio.com/downloads/Microsoft/Drivers/ChelsioUwire_6.16.17.0_WIN_006.0.106/Chelsio-UnifiedWire-Windows-UserGuide.pdf) <br> |
| Mellanox     | ConnectX-4 Lx            | [Windows](https://network.nvidia.com/products/adapter-software/ethernet/windows/winof-2/): WinOF-2 26.1.50000 <br> [Linux](https://developer.nvidia.com/doca-downloads?deployment_platform=Host-Server&deployment_package=DOCA-Host&target_os=Linux&Architecture=x86_64&Profile=doca-all&Distribution=Ubuntu&version=24.04&installer_type=deb_local): NVIDIA DOCA 3.3.0 | [Windows](https://docs.nvidia.com/networking/display/nvidiawinof2documentationv26150000/user-manual) <br> [Linux](https://docs.nvidia.com/doca/sdk/doca-installation-guide-for-linux/index.html) |
