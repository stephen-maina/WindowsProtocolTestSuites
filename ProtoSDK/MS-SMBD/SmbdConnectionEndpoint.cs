// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.RdmaLinux;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smbd
{
    /// <summary>
    /// The implementation-dependent representation used to access the RDMA connection.
    /// </summary>
    public class SmbdConnectionEndpoint : IDisposable
    {
        private const int THREAD_COUNT = 2;
        #region Fields
        private int receiveIndex = 0;
        private ReceiveEntry[] receiveEntries;

#if WINDOWS
        private INativeRdmaService rdmaService;
        private NdspiVersion ndVersion;
        private INativeRdmaProviderInfo[] rdmaProvidersList;
        private INativeRdmaAdapter rdmaAdapter;
        private INativeRdmaCompletionQueue rdmaCompletionQueue;
        private INativeRdmaConnector rdmaConnector;
        private INativeRdmaEndpoint rdmaEndpoint;
#else
        private RdmaLinuxAdapter linuxAdapter;
#endif
        private uint rdmaMaxInlineData;

        private NtStatus initializeStatus;
        private bool isConnected;

        private uint inboundEntries;
        private uint outboundEntries;
        private uint inboundSegment;
        private uint outboundSegment;
        private uint inboundReadLimit;
        private uint outboundReadLimit;
        private uint inboundDataSize;
        private uint completionQueueDepth;
        private List<SmbdMemoryWindow> memoryWindowList;
        /// <summary>
        /// Cached indicator of whether the RDMA provider supports memory windows.
        /// null = unknown, true = supported, false = not supported (use MR fallback).
        /// </summary>
        private bool? memoryWindowSupported;
        /// <summary>
        /// Receive and Invalid notification request list. The result of the request is from peer.
        /// </summary>
        private List<SmbdRequest> receiveRequestList;
        /// <summary>
        /// Result list of Send, SendAndInvalidate, Bind, Invalidate, Read, and Write requests
        /// </summary>
        private SyncFilterQueue<SmbdRequestResult> otherRequestResult;
        /// <summary>
        /// Result list of Receive request
        /// </summary>
        private SyncFilterQueue<SmbdRequestResult> receiveRequestResult;
        private Object locker;
        private SmbdLogEvent logEndpointEvent;
        /// <summary>
        /// Semaphore for waiting disconnect
        /// </summary>
        private Semaphore disconnectSemaphore;
        /// <summary>
        /// The main thread should wait util all the listen thread is started.
        /// 
        /// In main thread, WaitOne should be invoked to wait all thread is launched.
        /// In other thread, Release should be invoked to notify that the thread is launched.
        /// </summary>
        private Semaphore threadStartSemaphore;
        /// <summary>
        /// When client does RDMA notification, the request(Send, Send and Invalid, Receive, Invalid, Read and Write request)
        /// should be recorded.
        /// 
        /// In the NotifyCallback thread, it will invoke WaitOne to wait for client to submit work item.
        /// In the main thread, it will invoke Release to notify that the work item has been submitted.
        /// </summary>
        private Semaphore rdmaNotificationSemaphore;
        private int requestCount;
#endregion

        #region Properties
        public bool IsConnected { get { return isConnected; } }
        /// <summary>
        /// Count of receive request queued in Receive request result list
        /// </summary>
        public int ReceiveRequestsCount { get { return receiveRequestResult.Count; } }
        /// <summary>
        /// Count of receive has posted.
        /// </summary>
        public int ReceivePostedCount { get; protected set; }
        #endregion

        #region Private Helper Methods
        
     
        
        #endregion

        /// <summary>
        /// SmbdEndpoint constructor will load RDMA providers and initialize default connection values.
        /// </summary>
        /// <param name="inboundEntries">maximum number of outstanding Receive requests.</param>
        /// <param name="outboundEntries">maximum number of outstanding Send, SendAndInvalidate
        /// , Bind, Invalidate, Read, and Write requests.
        /// </param>
        /// <param name="inboundSegment">inbound segments limit</param>
        /// <param name="outboundSegment">outbound segments limit</param>
        /// <param name="inboundReadLimit">maximum inbound read limit for the local Network 
        /// Direct adapter. This value can be zero if you do not support
        /// </param>
        /// <param name="outboundReadLimit"></param>
        /// <param name="inboundDataSize">Max Size of RDMA inbound data</param>
        /// <param name="logEvent">Delegate to log SMBD event</param>
        public SmbdConnectionEndpoint(
            uint inboundEntries,
            uint outboundEntries,
            uint inboundSegment,
            uint outboundSegment,
            uint inboundReadLimit,
            uint outboundReadLimit,
            uint inboundDataSize,
            SmbdLogEvent logEvent = null,
            NdspiVersion ndVersion = NdspiVersion.NDv2
            )
        {
            this.logEndpointEvent = logEvent;

#if WINDOWS
            this.ndVersion = ndVersion;
            this.rdmaService = RdmaServiceFactory.Create(ndVersion);
            LogEvent(string.Format("Using NDSPI version {0}.", ndVersion));
            LogEvent("DIAGNOSTIC BUILD: SmbdConnectionEndpoint includes Bind resultId filter, descriptor dump, and requestType.");
            LogEvent("Loading the providers of registered network drivers.");
            initializeStatus = (NtStatus)rdmaService.LoadProviders(out rdmaProvidersList);

            this.inboundEntries = inboundEntries;
            this.outboundEntries = outboundEntries;
            this.inboundSegment = inboundSegment;
            this.outboundSegment = outboundSegment;
            this.inboundReadLimit = inboundReadLimit;
            this.outboundReadLimit = outboundReadLimit;
            this.completionQueueDepth = (inboundEntries + outboundEntries);
            this.inboundDataSize = inboundDataSize;


            isConnected = false;
            memoryWindowList = new List<SmbdMemoryWindow>();
            receiveRequestList = new List<SmbdRequest>();

            locker = new Object();

            otherRequestResult = new SyncFilterQueue<SmbdRequestResult>();
            receiveRequestResult = new SyncFilterQueue<SmbdRequestResult>();

            disconnectSemaphore = new Semaphore(0, 1);
            //threadStopSemaphore = new Semaphore(0, THREAD_COUNT);

            // one more for Semaphore Release when disconnection
            rdmaNotificationSemaphore = new Semaphore(0, (int)completionQueueDepth + 1);
            requestCount = 0;

            ReceivePostedCount = 0;

            #region output provider information
            if (initializeStatus != NtStatus.STATUS_SUCCESS)
            {
                LogEvent(string.Format("Load provider with error code: {0}", (NtStatus)initializeStatus));
                return;
            }
            if (rdmaProvidersList == null)
            {
                LogEvent("The returned providers list is NULL");
                return;
            }

            LogEvent(string.Format("{0} providers of registered network drivers have been load,", rdmaProvidersList.Length));
            int providerIndex = 0;
            foreach (INativeRdmaProviderInfo info in rdmaProvidersList)
            {
                if (info != null)
                {
                    LogEvent(string.Format("Load provider {1}: {0}", info.Path, ++providerIndex));
                }
            }
            LogEvent("Loading providers is completed");
            #endregion
#else
            // Initialize Linux RDMA adapter with comprehensive error handling
            try
            {
                this.inboundEntries = inboundEntries;
                this.outboundEntries = outboundEntries;
                this.inboundSegment = inboundSegment;
                this.outboundSegment = outboundSegment;
                this.inboundReadLimit = inboundReadLimit;
                this.outboundReadLimit = outboundReadLimit;
                this.completionQueueDepth = (inboundEntries + outboundEntries);
                this.inboundDataSize = inboundDataSize;

                isConnected = false;
                memoryWindowList = new List<SmbdMemoryWindow>();
                receiveRequestList = new List<SmbdRequest>();

                locker = new Object();

                otherRequestResult = new SyncFilterQueue<SmbdRequestResult>();
                receiveRequestResult = new SyncFilterQueue<SmbdRequestResult>();

                disconnectSemaphore = new Semaphore(0, 1);
                rdmaNotificationSemaphore = new Semaphore(0, (int)completionQueueDepth + 1);
                requestCount = 0;

                ReceivePostedCount = 0;

                this.linuxAdapter = new RdmaLinuxAdapter();
                LogEvent("Linux RDMA adapter initialized successfully.");
                initializeStatus = NtStatus.STATUS_SUCCESS;
            }
            catch (PlatformNotSupportedException ex)
            {
                LogEvent($"CRITICAL: Platform not supported for RDMA: {ex.Message}");
                LogEvent("Ensure RDMA drivers (librdmacm, libibverbs) are properly installed.");
                initializeStatus = NtStatus.STATUS_NOT_SUPPORTED;
                this.linuxAdapter = null;
            }
            catch (DllNotFoundException ex)
            {
                LogEvent($"CRITICAL: Native library not found: {ex.Message}");
                LogEvent("Ensure libRdmaLinuxAdapter.so is in the output directory.");
                initializeStatus = NtStatus.STATUS_DLL_NOT_FOUND;
                this.linuxAdapter = null;
            }
            catch (Exception ex)
            {
                LogEvent($"CRITICAL: Unexpected error initializing RDMA adapter: {ex.Message}");
                LogEvent($"Stack trace: {ex.StackTrace}");
                initializeStatus = NtStatus.STATUS_UNSUCCESSFUL;
                this.linuxAdapter = null;
            }
#endif
        }

        #region Public method
        /// <summary>
        /// establish connection over RDMA
        /// </summary>
        /// <param name="localIpAddress">local IP address</param>
        /// <param name="remoteIpAddress">remote IP address</param>
        /// <param name="port">port</param>
        /// <param name="ipFamily">IP Family</param>
        /// <returns></returns>
        public NtStatus ConnectToServerOverRdma(String localIpAddress, String remoteIpAddress, UInt16 port, AddressFamily ipFamily)
        {
            if (initializeStatus != NtStatus.STATUS_SUCCESS)
            {
                return initializeStatus;
            }
#if LINUX
            // Validate Linux RDMA adapter is initialized
            if (linuxAdapter == null)
            {
                LogEvent("CRITICAL: Linux RDMA adapter is not initialized.");
                LogEvent("Please check initialization logs for detailed error information.");
                return NtStatus.STATUS_NOT_SUPPORTED;
            }

            LogEvent($"Attempting to connect to {remoteIpAddress}:{port} via Linux RDMA...");
            var linuxStatus = linuxAdapter.Connect(remoteIpAddress, port);
            NtStatus status = RdmaStatusConverter.ToNtStatus(linuxStatus);
            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent($"CRITICAL: Linux RDMA connect failed with status {status}.");
                LogEvent($"Remote address: {remoteIpAddress}:{port}");
                return status;
            }

            LogEvent("Linux RDMA connection established successfully.");
            
            // Initialize data structures after successful connection
            isConnected = true;
            receiveEntries = new ReceiveEntry[inboundEntries];
            for (int i = 0; i < inboundEntries; i++)
            {
                receiveEntries[i] = new ReceiveEntry();
            }
            
            return NtStatus.STATUS_SUCCESS;
#endif

#if WINDOWS
            rdmaAdapter = OpenAdapter(rdmaProvidersList, localIpAddress, ipFamily);
            if (rdmaAdapter == null)
            {
                // this is the return code of NDSPI
                return NtStatus.STATUS_NOT_SUPPORTED;
            }

            // log adapter capabilities for diagnostics
            NdAdapterInfo adapterInfo;
            NtStatus queryStatus = (NtStatus)rdmaAdapter.Query(out adapterInfo);
            if (queryStatus == NtStatus.STATUS_SUCCESS && adapterInfo != null)
            {
                LogEvent(string.Format(
                    "Adapter capabilities: VendorId=0x{0:X4}, DeviceId=0x{1:X4}, " +
                    "MaxTransferLength={2}, MaxRegistrationSize={3}, MaxWindowSize={4}, " +
                    "MaxOutboundReadLimit={5}, MaxInboundReadLimit={6}, MaxInlineData={7}",
                    adapterInfo.VendorId,
                    adapterInfo.DeviceId,
                    adapterInfo.MaxTransferLength,
                    adapterInfo.MaxRegistrationSize,
                    adapterInfo.MaxWindowSize,
                    adapterInfo.MaxOutboundReadLimit,
                    adapterInfo.MaxInboundReadLimit,
                    adapterInfo.MaxInlineData));
            }
            else
            {
                LogEvent(string.Format("Adapter Query failed with status {0}", queryStatus));
            }

            // create completion queue
            NtStatus status = (NtStatus)rdmaAdapter.CreateCompletionQueue(
                this.completionQueueDepth,
                out this.rdmaCompletionQueue
                );
            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent($"CreateCompletionQueue failed with {status}.");

                return status;
            }

            // connector
            status = (NtStatus)rdmaAdapter.CreateConnector(out this.rdmaConnector);
            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent($"CreateConnector failed with {status}.");

                return status;
            }

            // create endpoint
            status = (NtStatus)rdmaConnector.CreateEndpoint(
                rdmaCompletionQueue,
                inboundEntries,
                outboundEntries,
                1,
                1,
                inboundReadLimit,
                0,
                out rdmaMaxInlineData,
                out rdmaEndpoint);

            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent($"CreateEndpoint failed with {status}.");

                return status;
            }

            // connect to server
            status = (NtStatus)rdmaConnector.Connect(rdmaEndpoint, remoteIpAddress, port, 6 /* for tcp */);
            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent($"Connect failed with {status}.");

                return status;
            }

            // complete connection and then can do RDMA operations
            status = (NtStatus)rdmaConnector.CompleteConnect();
            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent($"CompleteConnect failed with {status}.");

                return status;
            }

            CompleteConnect();
            return NtStatus.STATUS_SUCCESS;
#endif
        }

        /// <summary>
        /// listen and wait for peer connect
        /// </summary>
        /// <param name="localIpAddress"></param>
        /// <param name="port"></param>
        /// <param name="ipFamily">IP Family IPv4 or IPv6</param>
        /// <returns></returns>
        public NtStatus ListenConnection(String localIpAddress, ushort port, AddressFamily ipFamily)
        {
#if WINDOWS
            if (initializeStatus != NtStatus.STATUS_SUCCESS)
            {
                return initializeStatus;
            }

            rdmaAdapter = OpenAdapter(rdmaProvidersList, localIpAddress, ipFamily);
            if (rdmaAdapter == null)
            {
                // this is the return code of NDSPI
                return NtStatus.STATUS_NOT_SUPPORTED;
            }

            // listen and get incoming connection request
            INativeRdmaListen listen;
            NtStatus status = (NtStatus)rdmaAdapter.Listen(6/* tcp */, port, out listen);
            if (status != NtStatus.STATUS_SUCCESS)
            {
                return status;
            }

            // create connector
            status = (NtStatus)rdmaAdapter.CreateConnector(out rdmaConnector);
            if (status != NtStatus.STATUS_SUCCESS)
            {
                return status;
            }

            // wait for connection
            status = (NtStatus)listen.GetConnectionRequest(rdmaConnector);
            if (status != NtStatus.STATUS_SUCCESS)
            {
                return status;
            }

            // create completion queue and endpoint
            status = (NtStatus)rdmaAdapter.CreateCompletionQueue(this.completionQueueDepth, out this.rdmaCompletionQueue);
            if (status != NtStatus.STATUS_SUCCESS)
            {
                return status;
            }
            status = (NtStatus)this.rdmaConnector.CreateEndpoint(
                rdmaCompletionQueue,
                inboundEntries,
                outboundEntries,
                1,
                1,
                inboundReadLimit,
                0,
                out rdmaMaxInlineData,
                out rdmaEndpoint);
            if (status != NtStatus.STATUS_SUCCESS)
            {
                return status;
            }

            // accept the arrival RDMA connection
            status = (NtStatus)this.rdmaConnector.Accept(rdmaEndpoint);

            if (status != NtStatus.STATUS_SUCCESS)
            {
                return status;
            }

            CompleteConnect();
            return NtStatus.STATUS_SUCCESS;
#endif

#if LINUX
            // Linux platform does not support server mode in this implementation
            LogEvent("Linux RDMA server mode is not supported.");
            return NtStatus.STATUS_NOT_SUPPORTED;
#endif
        }

        /// <summary>
        /// Disconnect
        /// </summary>
        /// <returns></returns>
        public void Disconnect()
        {
            lock (locker)
            {
                if (isConnected == false)
                {
                    return;
                }
                isConnected = false;
            }

            // disconnect
#if LINUX
            if (linuxAdapter != null)
            {
                linuxAdapter.Disconnect();
                linuxAdapter.Dispose();
                linuxAdapter = null;
            }
#endif

#if WINDOWS
            rdmaConnector.Disconnect();
            // let notify thread stop
            rdmaNotificationSemaphore.Release();
            for (int i = 0; i < THREAD_COUNT; ++i)
            {
                //threadStopSemaphore.WaitOne(); // wait thread to stop
            }

            LogEvent("RDMA connection is disconnected by test suite.");
            this.logEndpointEvent = null;
#endif
        }

        /// <summary>
        /// Send data over RDMA
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public NtStatus SendData(byte[] data)
        {

#if LINUX
            if (linuxAdapter == null || !linuxAdapter.IsConnected)
            {
                LogEvent("Linux RDMA adapter is not connected.");
                return NtStatus.STATUS_CONNECTION_DISCONNECTED;
            }

            var linuxStatus = linuxAdapter.Send(data);
            LogEvent($"Send data status is {linuxStatus}");
            return RdmaStatusConverter.ToNtStatus(linuxStatus);
#endif

#if WINDOWS
            NdSegment sge = new NdSegment();
            sge.Length = (uint)data.LongLength;
            sge.MemoryHandler = 0;

            // register memory
            rdmaAdapter.RegisterMemory(sge.Length, out sge.MemoryHandler);
            // Write data to memory
            rdmaService.WriteToMemory(sge.MemoryHandler, data);

            // send
            UInt64 resultId;
            NtStatus status = (NtStatus)rdmaEndpoint.Send(new NdSegment[] { sge }, out resultId);
            if (status != NtStatus.STATUS_SUCCESS)
            {
                return status;
            }
            // send request has been submitted
            requestCount++;
            rdmaNotificationSemaphore.Release();

            // get the notification
            SmbdRequestResult item = GetRequestResult(new TimeSpan(0, 0, 5), RequestType.Send);
            this.LogEvent(string.Format("Send data with result id: 0x{0:X}. And get notification with id: 0x{1:X}, status: {2}",
                resultId,
                item.ResultId,
                item.ResultInfo.Status
                ));

            // deregister memory
            rdmaAdapter.DeregisterMemory(sge.MemoryHandler);

            return (NtStatus)item.ResultInfo.Status;
#endif
        }

        /// <summary>
        /// Receive data over RDMA
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public NtStatus ReceiveData(TimeSpan timeout, out byte[] data)
        {
            data = null;
            NtStatus status = NtStatus.STATUS_SUCCESS;
#if LINUX

            if (linuxAdapter == null || !linuxAdapter.IsConnected)
            {
                LogEvent("Linux RDMA adapter is not connected.");
                data = null;
                return NtStatus.STATUS_CONNECTION_DISCONNECTED;
            }

            // Poll for receive completion
            RdmaLinux.RdmaCompletion completion;
            var pollStatus = linuxAdapter.PollCompletion(out completion, (int)timeout.TotalMilliseconds,(int)RdmaLinuxOPCode.Recv);
            
            status = RdmaStatusConverter.ToNtStatus(pollStatus);
            LogEvent($"PollCompletion status is {status}");
            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent($"Linux RDMA receive failed or timed out. Status: {status}");
                data = null;
                return status;
            }

            // Validate completion data
            if (completion.wr_id >= ulong.MaxValue || completion.byte_len > (1024 * 1024)) // Sanity check: max 1MB
            {
                LogEvent($"Invalid completion data: wr_id={completion.wr_id}, byte_len={completion.byte_len}");
                data = null;
                return NtStatus.STATUS_INTERNAL_ERROR;
            }

            if (completion.status != 0) // IBV_WC_SUCCESS == 0
            {
                LogEvent($"RDMA receive work completion failed with status {completion.status}, vendor_err {completion.vendor_err}");
                data = null;
                return NtStatus.STATUS_CONNECTION_DISCONNECTED;
            }

            // Find the entry by wr_id (slot_id)
            LogEvent($"Find the receive entry index: {(int)completion.wr_id} and len:{completion.byte_len}");
            int entryIndex = (int)completion.wr_id;
            if (entryIndex < 0 || entryIndex >= receiveEntries.Length)
            {
                LogEvent($"Invalid receive entry index: {entryIndex}");
                data = null;
                return NtStatus.STATUS_INTERNAL_ERROR;
            }

            // Copy data from the registered buffer
            if (completion.byte_len > 0 && receiveEntries[entryIndex].LinuxBuffer != null)
            {
                // Validate that we have a valid buffer address
                if (receiveEntries[entryIndex].LinuxBufferAddress == 0)
                {
                    LogEvent($"Invalid buffer address for entry {entryIndex}");
                    data = null;
                    return NtStatus.STATUS_INTERNAL_ERROR;
                }

                data = new byte[completion.byte_len];
                // Copy from registered buffer address to managed array
                try
                {
                    Marshal.Copy((IntPtr)receiveEntries[entryIndex].LinuxBufferAddress, data, 0, (int)completion.byte_len);
                }
                catch (Exception ex)
                {
                    LogEvent($"Failed to copy data from buffer: {ex.Message}");
                    data = null;
                    return NtStatus.STATUS_INTERNAL_ERROR;
                }
                
                LogEvent($"Linux RDMA received {data.Length} bytes from entry {entryIndex}.");
            }
            else
            {
                data = new byte[0];
            }

            // Clean up this receive entry
            if (receiveEntries[entryIndex].LinuxMrHandle != 0)
            {
                var deregStatus = linuxAdapter.DeregisterMemory(receiveEntries[entryIndex].LinuxMrHandle);
                if (deregStatus != RdmaLinux.RdmaLinuxStatus.SUCCESS)
                {
                    LogEvent($"Failed to deregister memory for entry {entryIndex}: {deregStatus}");
                }
                receiveEntries[entryIndex].LinuxMrHandle = 0;
                receiveEntries[entryIndex].LinuxBuffer = null;
                receiveEntries[entryIndex].IsOccupied = false;
            }

            return status;
#endif

#if WINDOWS
            SmbdRequestResult item = GetRequestResult(timeout, RequestType.Receive);
            status = (NtStatus)item.ResultInfo.Status;

            if (status != NtStatus.STATUS_SUCCESS)
            {
                data = null;
                return status;
            }

            this.LogEvent(string.Format("Receive {0} bytes from entry 0x{1:X}",
                item.ResultInfo.BytesTransferred,
                item.EntryIndex));

            data = new byte[item.ResultInfo.BytesTransferred];

            status = (NtStatus)rdmaService.ReadFromMemory(
                this.receiveEntries[item.EntryIndex].Segment.MemoryHandler,
                data);

            // reset
            this.receiveEntries[receiveIndex].IsOccupied = false;
            return status;
#endif
        }

        /// <summary>
        /// Post Receive request
        /// </summary>
        /// <param name="bufferSize"></param>
        /// <returns></returns>
        public NtStatus PostReceive(uint bufferSize)
        {
            if (receiveEntries[receiveIndex].IsOccupied)
            {
                this.LogEvent("No more entries");
                // return no more entries. The error code is the same with RDMA
                return NtStatus.STATUS_NO_MORE_ENTRIES;
            }

            SmbdRequest receiveRequest = new SmbdRequest();
            receiveRequest.EntryIndex = receiveIndex;
            receiveRequest.Type = RequestType.Receive;
#if WINDOWS
            NtStatus ret = (NtStatus)rdmaEndpoint.Receive(
                new NdSegment[] { receiveEntries[receiveIndex].Segment },
                out receiveRequest.ResultId);

            if (ret != NtStatus.STATUS_SUCCESS)
            {
                this.LogEvent(string.Format("Raise receive request with error code {0}", ret));
                return ret;
            }
            // receive request has been submitted
            requestCount++;
            rdmaNotificationSemaphore.Release();

            lock (locker)
            {
                receiveRequestList.Add(receiveRequest);
                ReceivePostedCount++;
            }

            this.LogEvent(
                string.Format(
                    "Post receive successfully with entry 0x{0:X} with memory handler 0x{1:X} notification id: 0x{2:X}",
                    receiveIndex,
                    receiveEntries[receiveIndex].Segment.MemoryHandler,
                    receiveRequest.ResultId));
            receiveEntries[receiveIndex].IsOccupied = true;

            // calculate the index of next receive entry
            receiveIndex++;
            if ((UInt64)receiveIndex >= inboundEntries)
            {
                receiveIndex = 0;
            }
#endif
#if LINUX
            // Linux: Post receive buffer using the adapter layer
            if (linuxAdapter == null || !linuxAdapter.IsConnected)
            {
                LogEvent("Linux RDMA adapter is not connected.");
                return NtStatus.STATUS_CONNECTION_DISCONNECTED;
            }

            // Allocate receive buffer
            byte[] receiveBuffer = new byte[bufferSize];
            
            // Post receive and register the buffer
            ulong address;
            long mrHandle;
            var postStatus = linuxAdapter.PostReceive(receiveBuffer, (ulong)receiveIndex, out address, out mrHandle);
            
            if (postStatus != RdmaLinuxStatus.SUCCESS)
            {
                LogEvent($"Failed to post receive: {postStatus}");
                // Advance receiveIndex even on failure to avoid getting stuck on a busy slot
                receiveIndex++;
                if ((UInt64)receiveIndex >= inboundEntries)
                {
                    receiveIndex = 0;
                }
                return RdmaStatusConverter.ToNtStatus(postStatus);
            }

            // Store the MR handle and buffer for later data retrieval
            receiveEntries[receiveIndex].LinuxMrHandle = mrHandle;
            receiveEntries[receiveIndex].LinuxBufferAddress = address;
            receiveEntries[receiveIndex].LinuxBuffer = receiveBuffer;
            receiveEntries[receiveIndex].IsOccupied = true;

            LogEvent($"Post receive successfully with entry 0x{receiveIndex:X}, addr=0x{address:X}, len={bufferSize}");

            // Move to next receive entry
            receiveIndex++;
            if ((UInt64)receiveIndex >= inboundEntries)
            {
                receiveIndex = 0;
            }
#endif

            return NtStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Get result of request
        /// </summary>
        public SmbdRequestResult GetRequestResult(TimeSpan timeout, RequestType type)
        {
            if (type == RequestType.Receive)
            {
                return receiveRequestResult.Dequeue(timeout);
            }
            return otherRequestResult.Dequeue(timeout);
        }

        /// <summary>
        /// Register memory windows
        /// </summary>
        /// <param name="size">Size of memory to register</param>
        /// <param name="flag"></param>
        /// <param name="reversed">if it is true, little-endian and big-endian will be reversed in bufferDescriptor</param>
        /// <param name="bufferDescriptor">Buffer Descriptor point to memory windows</param>
        /// <returns></returns>
        public NtStatus RegisterMemoryWindow(uint size, uint flag, bool reversed, out RdmaBufferDescriptor bufferDescriptor)
        {
            bufferDescriptor = new RdmaBufferDescriptor();
            LogEvent(string.Format(
                "RegisterMemoryWindow called: size={0}, flag={1}, reversed={2}",
                size, flag, reversed));

#if LINUX
            if (linuxAdapter == null || !linuxAdapter.IsConnected)
            {
                LogEvent("Linux RDMA adapter is not connected.");
                return NtStatus.STATUS_CONNECTION_DISCONNECTED;
            }
               
            // Linux: Registering a memory window using the adapter layer
            byte[] buffer = new byte[size];
            long mwHandle;
            uint rkey;
            ulong address;
                
            var linuxStatus = linuxAdapter.RegisterMemory(buffer, flag, out mwHandle, out rkey, out address);
            NtStatus status = RdmaStatusConverter.ToNtStatus(linuxStatus);
            if (status != NtStatus.STATUS_SUCCESS)
                return status;

            bufferDescriptor = new RdmaBufferDescriptor
            {
                Offset = address,
                Token = rkey,
                Length = size
            };
            LogEvent($"Linux RDMA memory window registered: mwHandle={mwHandle}, rkey={rkey}, addr=0x{address:X}");
            return status;
#endif

#if WINDOWS
            // register the buffer
            SmbdMemoryWindow memoryWindow = new SmbdMemoryWindow();
            memoryWindow.IsValid = true;
            NtStatus status = (NtStatus)rdmaAdapter.RegisterMemory(size, out memoryWindow.MemoryHandlerId);
            LogEvent(string.Format(
                "RegisterMemoryWindow: RegisterMemory returned {0}, memoryHandlerId=0x{1:X}",
                status, memoryWindow.MemoryHandlerId));
            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent(string.Format("RegisterMemoryWindow: RegisterMemory failed with {0}", status));
                return status;
            }

            // If a previous call has already determined that memory windows are
            // unsupported by this provider, skip CreateMemoryWindow and build the
            // buffer descriptor directly from the registered memory region.
            if (memoryWindowSupported == false)
            {
                LogEvent("RegisterMemoryWindow: provider is cached as memory-window unsupported; using memory-region fallback.");
                return BuildMemoryRegionDescriptor(memoryWindow.MemoryHandlerId, reversed, out bufferDescriptor);
            }

            // create memory window
            SmbdRequest invalidRequest = new SmbdRequest();
            invalidRequest.Type = RequestType.Invalid;
            status = (NtStatus)rdmaAdapter.CreateMemoryWindow(invalidRequest.ResultId,
                out memoryWindow.RdmaMW);
            memoryWindow.InvalidResultId = invalidRequest.ResultId;
            LogEvent(string.Format(
                "RegisterMemoryWindow: CreateMemoryWindow returned {0}, invalidResultId=0x{1:X}",
                status, memoryWindow.InvalidResultId));
            if (status != NtStatus.STATUS_SUCCESS)
            {
                if (status == NtStatus.STATUS_NOT_SUPPORTED)
                {
                    // Fallback for providers that do not implement memory
                    // windows (e.g. Intel irdma / E810): advertise the
                    // registered memory region directly. The MR is registered
                    // with remote read and write permission, so SMB2
                    // READ/WRITE over RDMA still works; the remote access
                    // simply cannot be revoked per operation and stays valid
                    // until the buffer is deregistered.
                    memoryWindowSupported = false;
                    return BuildMemoryRegionDescriptor(memoryWindow.MemoryHandlerId, reversed, out bufferDescriptor);
                }

                LogEvent(string.Format("RegisterMemoryWindow: CreateMemoryWindow failed with {0}", status));
                CleanupFailedRegisterMemoryWindow(memoryWindow, invalidRequest, false, false);
                return status;
            }

            memoryWindowSupported = true;

            // invalid notification request has been submitted
            Interlocked.Increment(ref requestCount);
            rdmaNotificationSemaphore.Release();

            // bind
            this.LogEvent(string.Format("Binding memory window: size={0}, flag={1}, reversed={2}",
                size, flag, reversed));
            UInt64 resultId;
            status = (NtStatus)rdmaEndpoint.Bind(
                memoryWindow.MemoryHandlerId,
                memoryWindow.RdmaMW,
                (RdmaReadWriteFlag)flag,
                reversed,
                out memoryWindow.BufferDescriptor, out resultId);

            LogEvent(string.Format(
                "RegisterMemoryWindow: Bind returned {0}, resultId=0x{1:X}",
                status, resultId));
            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent(string.Format("RegisterMemoryWindow: Bind failed with {0}", status));
                CleanupFailedRegisterMemoryWindow(memoryWindow, invalidRequest, false, true);
                return status;
            }

            lock (locker)
            {
                this.receiveRequestList.Add(invalidRequest);
            }

            // NDSPI v2 Bind is asynchronous. Wait for the completion whose result id
            // matches the Bind request, otherwise a stale Send/Read/Write completion
            // could be dequeued first and the memory window token would be refreshed
            // before it is actually valid.
            SmbdRequestResult requestResult;
            try
            {
                requestResult = otherRequestResult.Dequeue(
                    new TimeSpan(0, 0, 5),
                    item => item.ResultId == resultId);
            }
            catch (TimeoutException ex)
            {
                LogEvent(string.Format(
                    "RegisterMemoryWindow: Timed out waiting for Bind completion with resultId=0x{0:X}. Exception: {1}",
                    resultId, ex.Message));
                CleanupFailedRegisterMemoryWindow(memoryWindow, invalidRequest, true, true);
                return NtStatus.STATUS_TIMEOUT;
            }

            this.LogEvent(string.Format("Bind memory window with expected result id: {0}. Actual notification id: {1}, status: {2}, requestType={3}",
                resultId,
                requestResult.ResultId,
                requestResult.ResultInfo.Status,
                requestResult.ResultInfo.RequestType
                ));

            status = (NtStatus)requestResult.ResultInfo.Status;
            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent(string.Format("RegisterMemoryWindow: Bind completion failed with status {0}", status));
                CleanupFailedRegisterMemoryWindow(memoryWindow, invalidRequest, true, true);
                return status;
            }

            // NDSPI v2: the memory window token may only become valid after the
            // Bind completion has been processed. Refresh the descriptor token
            // now that the bind is complete. For NDSPI v1 the property returns
            // the same token that was already placed in the descriptor.
            memoryWindow.BufferDescriptor.Token = memoryWindow.RdmaMW.RemoteToken;

            // Dump the descriptor as it will be placed on the wire (little-endian).
            byte[] descriptorBytes = new byte[16];
            BitConverter.GetBytes(memoryWindow.BufferDescriptor.Offset).CopyTo(descriptorBytes, 0);
            BitConverter.GetBytes(memoryWindow.BufferDescriptor.Token).CopyTo(descriptorBytes, 8);
            BitConverter.GetBytes(memoryWindow.BufferDescriptor.Length).CopyTo(descriptorBytes, 12);
            string descriptorHex = BitConverter.ToString(descriptorBytes).Replace("-", " ");

            LogEvent(string.Format("Bind completion descriptor: Offset=0x{0:X16}, Token=0x{1:X8}, Length={2}, Bytes=[{3}]",
                memoryWindow.BufferDescriptor.Offset,
                memoryWindow.BufferDescriptor.Token,
                memoryWindow.BufferDescriptor.Length,
                descriptorHex));

            lock (locker)
            {
                this.memoryWindowList.Add(memoryWindow);
            }
            bufferDescriptor = new RdmaBufferDescriptor
            {
                Offset = memoryWindow.BufferDescriptor.Offset,
                Token = memoryWindow.BufferDescriptor.Token,
                Length = memoryWindow.BufferDescriptor.Length,
            };
            LogEvent(string.Format(
                "RegisterMemoryWindow: returning descriptor Offset=0x{0:X16}, Token=0x{1:X8}, Length={2}",
                bufferDescriptor.Offset, bufferDescriptor.Token, bufferDescriptor.Length));
            return status;
#endif
        }

        /// <summary>
        /// Deregister memory window
        /// </summary>
        /// <param name="bufferDescriptor">Buffer Descriptor point to memory windows</param>
        /// <returns></returns>
        public void DeregisterMemoryWindow(RdmaBufferDescriptor bufferDescriptor)
        {
#if LINUX
            if (linuxAdapter == null || !linuxAdapter.IsConnected)
            {
                LogEvent("Linux RDMA adapter is not connected.");
                return;
            }
            
            foreach (var mw in linuxAdapter.EnumerateMemoryWindows())
            {
                if (mw.Token != bufferDescriptor.Token)
                {
                    continue;
                }
        
                if (mw.IsValid)
                {
                    ulong resultId;
                    var invalidateStatus = linuxAdapter.InvalidateMemoryWindow(mw.MemoryHandlerId, out resultId);
                    var linuxStatus = linuxAdapter.DeregisterMemory(mw.MemoryHandlerId);
                    NtStatus status = RdmaStatusConverter.ToNtStatus(linuxStatus);
                }
            }     
#endif

#if WINDOWS
            SmbdMemoryWindow target = null;
            lock (locker)
            {
                for (int i = 0; i < memoryWindowList.Count; ++i)
                {
                    if (memoryWindowList[i].BufferDescriptor.Token == bufferDescriptor.Token)
                    {
                        target = memoryWindowList[i];
                        memoryWindowList.RemoveAt(i);
                        break;
                    }
                }
            }

            if (target == null)
            {
                LogEvent(string.Format(
                    "DeregisterMemoryWindow: no memory window found with token 0x{0:X8}",
                    bufferDescriptor.Token));
                return;
            }

            // get memory window
            if (target.IsValid)
            {
                UInt64 resultId;
                NtStatus status = (NtStatus)rdmaEndpoint.Invalidate(target.RdmaMW, out resultId);

                if (status == NtStatus.STATUS_SUCCESS)
                {
                    Interlocked.Increment(ref requestCount);
                    rdmaNotificationSemaphore.Release();
                }
            }

            rdmaAdapter.DeregisterMemory(target.MemoryHandlerId);
            if (target.RdmaMW != null)
            {
                target.RdmaMW.Dispose();
            }
#endif
        }

#if WINDOWS
        /// <summary>
        /// Builds a buffer descriptor directly from a registered memory region.
        /// Used as a fallback when the RDMA provider does not support memory windows.
        /// </summary>
        private NtStatus BuildMemoryRegionDescriptor(ulong memoryHandler, bool reversed, out RdmaBufferDescriptor bufferDescriptor)
        {
            bufferDescriptor = new RdmaBufferDescriptor();

            RdmaRegisteredMemory mrInfo;
            int mrStatus = rdmaAdapter.GetRegisteredMemory(memoryHandler, out mrInfo);
            if (mrStatus != 0)
            {
                NtStatus deregisterStatus = (NtStatus)rdmaAdapter.DeregisterMemory(memoryHandler);
                LogEvent(string.Format(
                    "RegisterMemoryWindow: GetRegisteredMemory failed with 0x{0:X8}; deregistered memory handler 0x{1:X} with status {2}",
                    mrStatus, memoryHandler, deregisterStatus));
                return (NtStatus)mrStatus;
            }

            // The remote token of a memory region is the R_Key the provider hands
            // out for remote access; it is already in the byte order the peer
            // consumes and MUST NOT be byte-swapped here. The previous code applied
            // the 'reversed' swap, which corrupted the R_Key on Intel irdma/E810
            // (EndianOfBufferDescriptor=BigEndian) and made the server abort the
            // connection on every READ. The MW path above is unaffected: Bind's
            // 'reverse' flag lets the provider generate its descriptor in the
            // requested byte order.
            if (reversed)
            {
                LogEvent("RegisterMemoryWindow: WARNING - memory-region fallback ignores the 'reversed' byte swap; the MR R_Key is placed on the wire as-is. Configure EndianOfBufferDescriptor=LittleEndian for this provider.");
            }
            uint token = mrInfo.RemoteToken;

            SmbdMemoryWindow memoryWindow = new SmbdMemoryWindow
            {
                MemoryHandlerId = memoryHandler,
                RdmaMW = null,
                IsValid = false, // nothing to invalidate without a memory window
                BufferDescriptor = new RdmaBufferDescriptor
                {
                    Offset = mrInfo.Address,
                    Token = token,
                    Length = mrInfo.Length,
                }
            };

            lock (locker)
            {
                this.memoryWindowList.Add(memoryWindow);
            }

            bufferDescriptor = new RdmaBufferDescriptor
            {
                Offset = mrInfo.Address,
                Token = token,
                Length = mrInfo.Length,
            };
            LogEvent(string.Format(
                "RegisterMemoryWindow: returning memory-region descriptor Offset=0x{0:X16}, Token=0x{1:X8}, Length={2} (memory window not supported)",
                bufferDescriptor.Offset, bufferDescriptor.Token, bufferDescriptor.Length));
            return NtStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Cleans up resources allocated by RegisterMemoryWindow when it fails
        /// after memory (and optionally a memory window) has been allocated.
        /// </summary>
        private void CleanupFailedRegisterMemoryWindow(
            SmbdMemoryWindow memoryWindow,
            SmbdRequest invalidRequest,
            bool invalidRequestAdded,
            bool decrementRequestCount)
        {
            if (invalidRequestAdded)
            {
                lock (locker)
                {
                    this.receiveRequestList.RemoveAll(r => r.ResultId == invalidRequest.ResultId);
                }
            }

            if (decrementRequestCount)
            {
                Interlocked.Decrement(ref requestCount);
            }

            if (memoryWindow.RdmaMW != null)
            {
                memoryWindow.RdmaMW.Dispose();
                memoryWindow.RdmaMW = null;
            }

            if (memoryWindow.MemoryHandlerId != 0)
            {
                NtStatus deregisterStatus = (NtStatus)rdmaAdapter.DeregisterMemory(memoryWindow.MemoryHandlerId);
                LogEvent(string.Format(
                    "RegisterMemoryWindow: deregistered memory handler 0x{0:X} during cleanup with status {1}",
                    memoryWindow.MemoryHandlerId, deregisterStatus));
            }
        }
#endif

        /// <summary>
        /// Write data to memory window
        /// </summary>
        /// <param name="data"></param>
        /// <param name="bufferDescriptor">Buffer Descriptor point to memory windows</param>
        public NtStatus WriteMemoryWindow(byte[] data, RdmaBufferDescriptor bufferDescriptor)
        {
#if LINUX
            if (linuxAdapter == null || !linuxAdapter.IsConnected)
                return NtStatus.STATUS_CONNECTION_DISCONNECTED;

            IntPtr localAddr = (IntPtr)bufferDescriptor.Offset;
    
            Marshal.Copy(data, 0, localAddr, data.Length);
    
            LogEvent($"Linux RDMA data copied to local memory at 0x{bufferDescriptor.Offset:X}");
            return NtStatus.STATUS_SUCCESS;
#endif

#if WINDOWS
            SmbdMemoryWindow target = null;
            lock (locker)
            {
                foreach (SmbdMemoryWindow mw in memoryWindowList)
                {
                    if (mw.BufferDescriptor.Token == bufferDescriptor.Token)
                    {
                        target = mw;
                        break;
                    }
                }
            }

            if (target != null)
            {
                // Local write uses MemoryHandlerId, which is independent of remote MW validity.
                return (NtStatus)rdmaService.WriteToMemory(target.MemoryHandlerId, data);
            }
            return NtStatus.STATUS_INVALID_PARAMETER_2;
#endif

        }

        /// <summary>
        /// Read data from memory window
        /// </summary>
        /// <param name="data"></param>
        /// <param name="bufferDescriptor">Buffer Descriptor point to memory windows</param>
        public NtStatus ReadMemoryWindow(byte[] data, RdmaBufferDescriptor bufferDescriptor)
        {
#if LINUX
            if (linuxAdapter == null || !linuxAdapter.IsConnected)
            {
                LogEvent("Linux RDMA adapter is not connected.");
                return NtStatus.STATUS_CONNECTION_DISCONNECTED;
            }

            foreach (var mw in linuxAdapter.EnumerateMemoryWindows())
            {
                if (mw.Token != bufferDescriptor.Token)
                {
                    continue;
                }
        
                // Local read uses MemoryHandlerId, which is independent of remote MW validity.
                NtStatus status = linuxAdapter.ReadFromMemory(mw.MemoryHandlerId, data);
                LogEvent($"Linux RDMA read completed. Status: {status}");
                return status;
            }

            return NtStatus.STATUS_INVALID_PARAMETER_2;
#endif

#if WINDOWS
            SmbdMemoryWindow target = null;
            lock (locker)
            {
                foreach (SmbdMemoryWindow mw in memoryWindowList)
                {
                    if (mw.BufferDescriptor.Token == bufferDescriptor.Token)
                    {
                        target = mw;
                        break;
                    }
                }
            }

            if (target != null)
            {
                // Local read uses MemoryHandlerId, which is independent of remote MW validity.
                NtStatus status = (NtStatus)rdmaService.ReadFromMemory(target.MemoryHandlerId, data);
                LogEvent($"Windows RDMA read completed. Status: {status}");
                return status;
            }

            return NtStatus.STATUS_INVALID_PARAMETER_2;
#endif
        }

        /// <summary>
        /// Wait until network is disconnected, using a TimeSpan to specify the time interval.
        /// </summary>
        /// <param name="timeout"></param>
        public void WaitDisconnect(TimeSpan timeout)
        {
#if WINDOWS
            disconnectSemaphore.WaitOne(timeout);
#elif LINUX
            if (linuxAdapter != null)
            {
                // Use Linux adapter's wait for disconnect method
                bool disconnected = linuxAdapter.WaitForDisconnect((int)timeout.TotalMilliseconds);
                if (disconnected)
                {
                    isConnected=false;
                    LogEvent("Disconnected detected by Linux adapter wait method");
                }
                else
                {
                    LogEvent("Timeout reached while waiting for disconnect");
                }
            }
#endif
        }

        #region IDisposable Members
        public void Dispose()
        {
            this.Disconnect();
        }
        #endregion

#endregion
#if WINDOWS
        /// <summary>
        /// Open adapter with local IP address
        /// </summary>
        /// <param name="providers"></param>
        /// <param name="localIpAddress"></param>
        /// <param name="ipFamily">IP Family, IPv4 or IPv6</param>
        /// <returns></returns>
        private INativeRdmaAdapter OpenAdapter(
            INativeRdmaProviderInfo[] providers,
            string localIpAddress,
            AddressFamily ipFamily)
        {
            INativeRdmaAdapter adapter;

            if (providers == null)
            {
                LogEvent("Providers list is null. Open adapter failed.");

                return null;
            }
            foreach (INativeRdmaProviderInfo providerInfo in providers)
            {
                if (providerInfo.Provider == null)
                {
                    continue;
                }

                LogEvent(string.Format("Try to open adapter from provider \"{0}\" with specific IP Address: \"{1}\"",
                        providerInfo.Path,
                        localIpAddress));

                OutputAddressInfoSupportedByProvider(providerInfo);

                NtStatus status = (NtStatus)providerInfo.Provider.OpenAdapter(localIpAddress, (short)ipFamily, out adapter);
                if (status != NtStatus.STATUS_SUCCESS)
                {
                    LogEvent(string.Format("Provider '{0}' does not support IP address \"{1}\".",
                            providerInfo.Path,
                            localIpAddress));

                    continue;
                }
                LogEvent(string.Format("Adapter on IP address \"{0}\" is open via provider '{1}'.",
                        localIpAddress,
                        providerInfo.Path));

                return adapter;
            }
            LogEvent(string.Format("IP address \"{0}\" is not supported by all providers. Open adapter failed.", localIpAddress));

            return null;
        }

        /// <summary>
        /// output all addresses which are supported by the provider
        /// </summary>
        private void OutputAddressInfoSupportedByProvider(INativeRdmaProviderInfo providerInfo)
        {
            if (providerInfo == null)
            {
                LogEvent("ProviderInfo is null.");
                return;
            }

            NdAddress[] addressList;
            NtStatus status = (NtStatus)providerInfo.Provider.QueryAddressList(out addressList);

            if (status != NtStatus.STATUS_SUCCESS)
            {
                LogEvent(string.Format("Return code of Provider.QueryAddressList is {0}", status));
                return;
            }

            if (addressList == null)
            {
                LogEvent("The address list returned from Provider.QueryAddressList is null.");
                return;
            }

            if (addressList.Length == 0)
            {
                LogEvent(string.Format("No address supported by provider \"{0}\".", providerInfo.Path));
                return;
            }

            LogEvent(string.Format("Total {0} addresses supported by the provider \"{1}\":\n",
                addressList.Length,
                providerInfo.Path));
            int addressIndex = 0;
            foreach (NdAddress address in addressList)
            {
                if (address == null)
                {
                    continue;
                }

                if ((AddressFamily)address.Family == AddressFamily.InterNetwork)
                { // IPv4
                    LogEvent(string.Format("{0}. {1}: {2}.{3}.{4}.{5}\n",
                        ++addressIndex,
                        AddressFamily.InterNetwork,
                        (byte)address.Data[0],
                        (byte)address.Data[1],
                        (byte)address.Data[2],
                        (byte)address.Data[3]));
                }
                else
                {
                    LogEvent(string.Format("{0}. {1}", ++addressIndex, (AddressFamily)address.Family));
                }
            }
        }

#region Callback
        /// <summary>
        /// Notify callback
        /// </summary>
        private void NotifyCallback(Object stateInfo)
        {
            // notify main thread, NotifyCallback is started.
            threadStartSemaphore.Release();
            LogEvent("NotifyCallback is started...");

            while (true)
            {
                // Wait for submitting request or disconnection
                rdmaNotificationSemaphore.WaitOne();
                rdmaNotificationSemaphore.Release();

                if (requestCount <= 0)
                { // no request in the list, the semaphore is released from disconnection
                    //threadStopSemaphore.Release();
                    LogEvent("NotifyCallback has stopped.");
                    return;
                }

                NtStatus status = (NtStatus)rdmaCompletionQueue.Notify();
                LogEvent(string.Format("NotifyCallback: get notification with status {0}.", status));
                if (status != NtStatus.STATUS_SUCCESS)
                {
                    continue;
                }

                while (true)
                {
                    UInt64 resultId;
                    NdResult ndResult;
                    UInt64 size = rdmaCompletionQueue.GetResult(out resultId, out ndResult);

                    if (size == 0)
                    {
                        break;
                    }
                    // WaitOne for reduce the request count
                    rdmaNotificationSemaphore.WaitOne();
                    Interlocked.Decrement(ref requestCount);

                    RequestType type = RequestType.None;
                    int segmentIndex = -1;
                    #region Receive and invalid memory window
                    lock (locker)
                    {
                        foreach (SmbdRequest request in receiveRequestList)
                        {
                            if (request.ResultId == resultId)
                            {
                                type = request.Type;
                                segmentIndex = request.EntryIndex;

                                // get the result
                                SmbdRequestResult requestResultItem = new SmbdRequestResult();
                                requestResultItem.EntryIndex = request.EntryIndex;
                                requestResultItem.ResultInfo = ndResult;
                                requestResultItem.ResultId = request.ResultId;

                                switch (request.Type)
                                {
                                    case RequestType.Receive:
                                        receiveRequestResult.Enqueue(requestResultItem);
                                        ReceivePostedCount--;
                                        break;
                                    case RequestType.Invalid:
                                        lock (locker)
                                        {
                                            for (int i = 0; i < memoryWindowList.Count; ++i)
                                            {
                                                if (memoryWindowList[i].InvalidResultId == request.ResultId)
                                                {
                                                    memoryWindowList[i].IsValid = false;
                                                }
                                            }
                                        }
                                        break;
                                }

                                receiveRequestList.Remove(request);
                                break;
                            }
                        }
                    }
                    #endregion
                    if (type == RequestType.None)
                    {
                        otherRequestResult.Enqueue(
                            new SmbdRequestResult()
                            {
                                ResultId = resultId,
                                ResultInfo = ndResult
                            });
                    }

                    // log
                    this.LogEvent(
                        string.Format(
                        "1 operation {0} has been finished with result {1} and result Id: {2:X};" +
                        " requestType={6}; Bytes of data transferred is {3}; Segment Index is {4}; Count of work items is {5}",
                            type,
                            (NtStatus)ndResult.Status,
                            resultId,
                            ndResult.BytesTransferred,
                            segmentIndex,
                            this.receiveRequestList.Count,
                            ndResult.RequestType));
                }
            }
        }

        /// <summary>
        /// notify disconnect
        /// </summary>
        /// <param name="stateInfo"></param>
        private void NotifyDisconnectCallBack(Object stateInfo)
        {
            // notify the main thread, Notify Disconnec Callback is started.
            threadStartSemaphore.Release();
            LogEvent("NotifyDisconnectCallBack is started...");

            while (true)
            {
                NtStatus status = (NtStatus)rdmaConnector.NotifyDisconnect();
                LogEvent(string.Format("Get the notification with status {0}", status));
                if (isConnected == false)
                {
                    disconnectSemaphore.Release();

                    LogEvent("NotifyDisconnectCallBack has stopped.");
                    return;
                }
                if (status == NtStatus.STATUS_SUCCESS)
                {
                    lock (locker)
                    {
                        if (isConnected == false)
                        {
                            // threadStopSemaphore.Release();
                            LogEvent("NotifyDisconnectCallBack has stopped.");
                            return;
                        }
                        isConnected = false;
                    }
                    disconnectSemaphore.Release();
                    LogEvent("RDMA connection is disconnected by server.");

                    // let notify thread stop
                    rdmaNotificationSemaphore.Release();

                    LogEvent("NotifyDisconnectCallBack has stopped.");
                    return;
                }
            }
        }
        #endregion

        /// <summary>
        /// Complete the work of connection
        /// </summary>
        private void CompleteConnect()
        {
            #region Require resource
            receiveEntries = new ReceiveEntry[inboundEntries];
            for (int i = 0; (UInt64)i < inboundEntries; ++i)
            {
                receiveEntries[i].Segment = new NdSegment();
                receiveEntries[i].Segment.Length = inboundDataSize;
                receiveEntries[i].IsOccupied = false;
                NtStatus ret = (NtStatus)rdmaAdapter.RegisterMemory(
                        receiveEntries[i].Segment.Length,
                        out receiveEntries[i].Segment.MemoryHandler);
                LogEvent(string.Format("Entry 0x{0:X} register with memory handler 0x{1:X}.",
                    i,
                    receiveEntries[i].Segment.MemoryHandler));

                if (ret != NtStatus.STATUS_SUCCESS)
                {
                    inboundEntries = (uint)i;
                    continue;
                }
            }
            LogEvent(string.Format("{0} entries resource has been required.", inboundEntries));

            #endregion
            LogEvent(string.Format("Register {0} blocks memory", inboundEntries));

            isConnected = true;
            threadStartSemaphore = new Semaphore(0, THREAD_COUNT);

            ThreadPool.QueueUserWorkItem(new WaitCallback(this.NotifyDisconnectCallBack));
            ThreadPool.QueueUserWorkItem(new WaitCallback(this.NotifyCallback));

            for (int i = 0; i < THREAD_COUNT; ++i)
            {
                threadStartSemaphore.WaitOne();
            }
            LogEvent("All callback threads has launched.");
        }
#endif

        /// <summary>
        /// log event
        /// </summary>
        /// <param name="str"></param>
        private void LogEvent(string str)
        {
            // log
            if (logEndpointEvent != null)
            {
                this.logEndpointEvent(str);
            }
        }
    }
    /// <summary>
    /// Rdma status.
    /// </summary>
    public enum RdmaStatus : int
    {
        RDMA_OK = 0,
        RDMA_ERR_GENERAL = -1,
        RDMA_ERR_TIMEOUT = -2,
        RDMA_ERR_INVALID_ARGUMENT = -3,
        RDMA_ERR_CONNECTION_CLOSED = -4,
        RDMA_ERR_NO_COMPLETION = -5,
        RDMA_ERR_RESOURCE = -6
    }
    /// <summary>
    /// 
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct RdmaCompletion
    {
        public ulong wr_id;
        public uint status;
        public uint byte_len;
        public uint qp_num;
        public uint op_code;
        public uint vendor_err;
    }
}
