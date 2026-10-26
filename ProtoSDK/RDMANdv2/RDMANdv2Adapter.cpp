// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// RDMANdv2.h includes <ndspi.h>, which brings in <winsock2.h> in the
// correct order. Including <winsock2.h> a second time (or before
// RDMANdv2.h) reintroduces winsock.h/winsock2.h conflicts.
#include "RDMANdv2.h"
#include <string.h>

using namespace System;
using namespace System::Runtime::InteropServices;

BEGIN_RDMA_NAMESPACE

RdmaAdapter::~RdmaAdapter()
{
    ReleaseRegisterMemory();

    if (_memoryHandlerList != NULL)
    {
        delete _memoryHandlerList;
        _memoryHandlerList = NULL;
    }

    if (_memoryHandlerLock != NULL)
    {
        DeleteCriticalSection(_memoryHandlerLock);
        delete _memoryHandlerLock;
        _memoryHandlerLock = NULL;
    }

    if (_hAdapterFile != NULL && _hAdapterFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(_hAdapterFile);
        _hAdapterFile = NULL;
    }

    if (_pOverlapped != NULL)
    {
        CloseHandle(_pOverlapped->hEvent);
        delete _pOverlapped;
        _pOverlapped = NULL;
    }

    if (_adapter != NULL)
    {
        _adapter->Release();
        _adapter = NULL;
    }
}

HRESULT RdmaAdapter::Query([Out]RdmaAdapterInfo^% adapterInformation)
{
    ND2_ADAPTER_INFO info;
    memset(&info, 0, sizeof(info));
    info.InfoVersion = 1;
    ULONG size = sizeof(info);

    HRESULT result = _adapter->Query(&info, &size);
    if (result != ND_SUCCESS)
    {
        return result;
    }

    adapterInformation = gcnew RdmaAdapterInfo();
    adapterInformation->VendorId                = info.VendorId;
    adapterInformation->DeviceId                = info.DeviceId;
    adapterInformation->MaxInboundSge           = (unsigned __int32)info.MaxReceiveSge;
    adapterInformation->MaxInboundRequests      = (unsigned __int32)info.MaxReceiveQueueDepth;
    adapterInformation->MaxInboundLength        = (unsigned __int32)info.MaxTransferLength;
    adapterInformation->MaxOutboundSge          = (unsigned __int32)info.MaxInitiatorSge;
    adapterInformation->MaxOutboundRequests     = (unsigned __int32)info.MaxInitiatorQueueDepth;
    adapterInformation->MaxOutboundLength       = (unsigned __int32)info.MaxTransferLength;
    adapterInformation->MaxInlineData           = (unsigned __int32)info.MaxInlineDataSize;
    adapterInformation->MaxInboundReadLimit     = (unsigned __int32)info.MaxInboundReadLimit;
    adapterInformation->MaxOutboundReadLimit    = (unsigned __int32)info.MaxOutboundReadLimit;
    adapterInformation->MaxCqEntries            = (unsigned __int32)info.MaxCompletionQueueDepth;
    adapterInformation->MaxRegistrationSize     = (unsigned __int32)info.MaxRegistrationSize;
    adapterInformation->MaxWindowSize           = (unsigned __int32)info.MaxWindowSize;
    adapterInformation->LargeRequestThreshold   = (unsigned __int32)info.LargeRequestThreshold;
    adapterInformation->MaxCallerData           = (unsigned __int32)info.MaxCallerData;
    adapterInformation->MaxCalleeData           = (unsigned __int32)info.MaxCalleeData;

    System::Diagnostics::Trace::WriteLine(System::String::Format(
        "RDMANdv2::Query adapter caps: VendorId=0x{0:X4}, DeviceId=0x{1:X4}, "
        "MaxTransferLength={2}, MaxRegistrationSize={3}, MaxWindowSize={4}, "
        "MaxOutboundReadLimit={5}, MaxInboundReadLimit={6}, MaxInlineData={7}",
        info.VendorId,
        info.DeviceId,
        info.MaxTransferLength,
        info.MaxRegistrationSize,
        info.MaxWindowSize,
        info.MaxOutboundReadLimit,
        info.MaxInboundReadLimit,
        info.MaxInlineDataSize));

    return ND_SUCCESS;
}

HRESULT RdmaAdapter::CreateCompletionQueue(
    unsigned __int32 entrySize,
    [Out]RdmaCompletionQueue^% completionQueue)
{
    IND2CompletionQueue *pCompletionQueue = NULL;

    HRESULT result = _adapter->CreateCompletionQueue(
        IID_IND2CompletionQueue,
        _hAdapterFile,
        (ULONG)entrySize,
        0,
        0,
        reinterpret_cast<void**>(&pCompletionQueue));

    if (result != ND_SUCCESS)
    {
        return result;
    }

    completionQueue = gcnew RdmaCompletionQueue(pCompletionQueue);
    return ND_SUCCESS;
}

HRESULT RdmaAdapter::RegisterMemory(unsigned __int32 bufferSize, [Out]unsigned __int64% memoryHandler)
{
    return RegisterMemory(bufferSize, RdmaOperationReadWriteFlag::ReadAndWrite, memoryHandler);
}

HRESULT RdmaAdapter::RegisterMemory(
    unsigned __int32 bufferSize,
    RdmaOperationReadWriteFlag flag,
    [Out]unsigned __int64% memoryHandler)
{
    memoryHandler = 0;
    ULONG accessFlags = ND_MR_FLAG_ALLOW_LOCAL_WRITE;
    switch (flag)
    {
    case RdmaOperationReadWriteFlag::Read:
        accessFlags |= ND_MR_FLAG_ALLOW_REMOTE_READ;
        break;
    case RdmaOperationReadWriteFlag::Write:
        accessFlags |= ND_MR_FLAG_ALLOW_REMOTE_WRITE;
        break;
    case RdmaOperationReadWriteFlag::ReadAndWrite:
        accessFlags |= ND_MR_FLAG_ALLOW_REMOTE_READ | ND_MR_FLAG_ALLOW_REMOTE_WRITE;
        break;
    default:
        return E_INVALIDARG;
    }

    IND2MemoryRegion *pMemoryRegion = NULL;
    HRESULT result = _adapter->CreateMemoryRegion(
        IID_IND2MemoryRegion,
        _hAdapterFile,
        reinterpret_cast<void**>(&pMemoryRegion));
    if (result != ND_SUCCESS)
    {
        return result;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    SIZE_T pageSize = sysInfo.dwPageSize;
    SIZE_T registeredLength = ((bufferSize + pageSize - 1) / pageSize) * pageSize;
    if (registeredLength < bufferSize)
    {
        // Overflow guard.
        pMemoryRegion->Release();
        return E_INVALIDARG;
    }

    void *buffer = VirtualAlloc(NULL, registeredLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL)
    {
        pMemoryRegion->Release();
        return HRESULT_FROM_WIN32(GetLastError());
    }

    result = pMemoryRegion->Register(
        buffer,
        registeredLength,
        accessFlags,
        _pOverlapped);

    if (result == ND_PENDING)
    {
        result = pMemoryRegion->GetOverlappedResult(_pOverlapped, TRUE);
    }

    if (result != ND_SUCCESS)
    {
        pMemoryRegion->Release();
        VirtualFree(buffer, 0, MEM_RELEASE);
        return result;
    }

    RdmaMrHandler *newElem = new RdmaMrHandler;
    memset(newElem, 0, sizeof(RdmaMrHandler));
    newElem->MemoryRegion = pMemoryRegion;
    newElem->Buffer = buffer;
    newElem->Length = bufferSize;
    newElem->RegisteredLength = (unsigned __int32)registeredLength;
    newElem->LocalToken = pMemoryRegion->GetLocalToken();
    newElem->RemoteToken = pMemoryRegion->GetRemoteToken();
    newElem->MagicNumber = RDMA_MAGIC_NUM;

    System::Diagnostics::Trace::WriteLine(System::String::Format(
        "RDMANdv2::RegisterMemory handler=0x{0:X}, buffer=0x{1:X}, length={2}, "
        "localToken=0x{3:X8}, remoteToken(MR)=0x{4:X8}",
        (unsigned __int64)newElem,
        (unsigned __int64)buffer,
        bufferSize,
        newElem->LocalToken,
        newElem->RemoteToken));

    EnterCriticalSection(_memoryHandlerLock);
    newElem->Prev = _memoryHandlerList;
    newElem->Next = _memoryHandlerList->Next;
    if (_memoryHandlerList->Next != NULL)
    {
        _memoryHandlerList->Next->Prev = newElem;
    }
    _memoryHandlerList->Next = newElem;
    LeaveCriticalSection(_memoryHandlerLock);

    memoryHandler = (unsigned __int64)newElem;
    return ND_SUCCESS;
}

HRESULT RdmaAdapter::DeregisterMemory(unsigned __int64 memoryHandler)
{
    RdmaMrHandler *elem = NULL;
    HRESULT result = GetMemoryHandler(memoryHandler, &elem);
    if (result != ND_SUCCESS)
    {
        return result;
    }

    result = elem->MemoryRegion->Deregister(_pOverlapped);
    if (result == ND_PENDING)
    {
        result = elem->MemoryRegion->GetOverlappedResult(_pOverlapped, TRUE);
    }

    if (result != ND_SUCCESS)
    {
        return result;
    }

    elem->MemoryRegion->Release();
    VirtualFree(elem->Buffer, 0, MEM_RELEASE);

    EnterCriticalSection(_memoryHandlerLock);
    elem->Prev->Next = elem->Next;
    if (elem->Next != NULL)
    {
        elem->Next->Prev = elem->Prev;
    }
    elem->MagicNumber = 0;
    LeaveCriticalSection(_memoryHandlerLock);
    delete elem;
    return result;
}

HRESULT RdmaAdapter::CreateMemoryWindow([Out]unsigned __int64 invalidateResult, [Out]RdmaMemoryWindow^% memoryWindow)
{
    IND2MemoryWindow *pMw = NULL;
    HRESULT result = _adapter->CreateMemoryWindow(
        IID_IND2MemoryWindow,
        reinterpret_cast<void**>(&pMw));
    if (result != ND_SUCCESS)
    {
        return result;
    }

    unsigned __int64 id = ++_nextInvalidateId;
    if (id == 0)
    {
        id = ++_nextInvalidateId;
    }
    invalidateResult = id;

    memoryWindow = gcnew RdmaMemoryWindow(pMw, id);
    return ND_SUCCESS;
}

HRESULT RdmaAdapter::GetRegisteredMemory(
    unsigned __int64 memoryHandler,
    [Out]RdmaRegisteredMemoryInfo^% info)
{
    RdmaMrHandler *elem = NULL;
    HRESULT result = GetMemoryHandler(memoryHandler, &elem);
    if (result != ND_SUCCESS)
    {
        return result;
    }

    info = gcnew RdmaRegisteredMemoryInfo();
    info->Address = (unsigned __int64)elem->Buffer;
    info->RemoteToken = elem->RemoteToken;
    info->Length = elem->Length;

    System::Diagnostics::Trace::WriteLine(System::String::Format(
        "RDMANdv2::GetRegisteredMemory handler=0x{0:X}, address=0x{1:X}, remoteToken(MR)=0x{2:X8}, length={3}",
        memoryHandler, info->Address, info->RemoteToken, info->Length));

    return ND_SUCCESS;
}

HRESULT RdmaAdapter::CreateConnector([Out]RdmaConnector^% connector)
{
    IND2Connector *nativeConnector = NULL;
    HRESULT result = _adapter->CreateConnector(
        IID_IND2Connector,
        _hAdapterFile,
        reinterpret_cast<void**>(&nativeConnector));
    if (result != ND_SUCCESS)
    {
        return result;
    }

    connector = gcnew RdmaConnector(nativeConnector, this);
    return ND_SUCCESS;
}

HRESULT RdmaAdapter::Listen(int protocol, unsigned __int16 port, [Out]RdmaListen^% listen)
{
    IND2Listener *pListen = NULL;
    HRESULT result = _adapter->CreateListener(
        IID_IND2Listener,
        _hAdapterFile,
        reinterpret_cast<void**>(&pListen));
    if (result != ND_SUCCESS)
    {
        return result;
    }

    sockaddr_in localAddr = {0};
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(port);
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    result = pListen->Bind((const sockaddr*)&localAddr, sizeof(localAddr));
    if (result != ND_SUCCESS)
    {
        pListen->Release();
        return result;
    }

    result = pListen->Listen(0);
    if (result != ND_SUCCESS)
    {
        pListen->Release();
        return result;
    }

    listen = gcnew RdmaListen(pListen);
    return ND_SUCCESS;
}

void RdmaAdapter::ReleaseRegisterMemory()
{
    HRESULT result = ND_SUCCESS;
    EnterCriticalSection(_memoryHandlerLock);
    while (_memoryHandlerList->Next != NULL)
    {
        result = DeregisterMemory((unsigned __int64)_memoryHandlerList->Next);
        if (result != ND_SUCCESS)
        {
            break;
        }
    }
    LeaveCriticalSection(_memoryHandlerLock);
    if (result != ND_SUCCESS)
    {
        throw gcnew InvalidOperationException(String::Format(
            "RDMA memory deregistration failed with 0x{0:X8}; registered storage remains owned.",
            result));
    }
}

RdmaAdapter::RdmaAdapter(IND2Adapter *adapter)
{
    _adapter = adapter;
    _hAdapterFile = NULL;
    _memoryHandlerList = new RdmaMrHandler;
    memset(_memoryHandlerList, 0, sizeof(RdmaMrHandler));
    _memoryHandlerList->Prev = NULL;
    _memoryHandlerList->Next = NULL;
    _memoryHandlerLock = new CRITICAL_SECTION;
    InitializeCriticalSection(_memoryHandlerLock);

    _pOverlapped = new OVERLAPPED;
    _pOverlapped->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    _nextInvalidateId = 0;

    HANDLE hAdapterFile = NULL;
    HRESULT hr = _adapter->CreateOverlappedFile(&hAdapterFile);
    if (SUCCEEDED(hr) && hAdapterFile != NULL)
    {
        _hAdapterFile = hAdapterFile;
    }
    else
    {
        _hAdapterFile = INVALID_HANDLE_VALUE;
    }
}

HRESULT RdmaAdapter::GetMemoryHandler(unsigned __int64 memoryID, RdmaMrHandler **memoryHandler)
{
    *memoryHandler = (RdmaMrHandler *)memoryID;
    if (*memoryHandler == NULL || (*memoryHandler)->MagicNumber != RDMA_MAGIC_NUM)
    {
        return ND_INVALID_PARAMETER;
    }

    return ND_SUCCESS;
}

END_RDMA_NAMESPACE
