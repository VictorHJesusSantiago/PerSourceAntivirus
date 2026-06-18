/*++

Module Name:
    PerSourceAntivirus.Driver.c

Abstract:
    Windows Kernel Minifilter Driver for PerSourceAntivirus.
    Intercepts IRP_MJ_CREATE (pre-create), reads the first 4 KB of the
    target file, and sends the file path + contents to the user-mode
    C# service via a filter communication port (\PSAVScanPort).
    The service replies with a SafeToOpen flag; on denial the IRP is
    completed with STATUS_ACCESS_DENIED.  Clean file IDs are cached in
    a flat 1024-bucket array (hash = FileId % 1024) to avoid re-scanning.

    Additionally registers:
      - PsSetCreateProcessNotifyRoutineEx  for process create/terminate events
      - PsSetLoadImageNotifyRoutine        for image (DLL/EXE) load events
      - ObRegisterCallbacks                to strip injection-capable access rights
    These stream kernel events to user mode via a second port (\PSAVEventPort)
    asynchronously with a 500 ms timeout (non-blocking from the callback side).

Environment:
    Kernel mode only.

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not modelling kernel")

/* -----------------------------------------------------------------------
   Shared structures  (pack(1) so the C# side can use the same layout)
   --------------------------------------------------------------------- */
#pragma pack(push, 1)

#define PSAV_READ_BUFFER_SIZE   4096U
#define PSAV_FILENAME_MAX       512U
#define PSAV_POOL_TAG           'VSAP'

/* --- Existing file-scan structures (unchanged) --- */

typedef struct _PSAV_NOTIFICATION {
    FILTER_MESSAGE_HEADER   Header;
    ULONG                   BytesToScan;
    ULONG                   Flags;
    WCHAR                   FileName[PSAV_FILENAME_MAX];   /* full NT path */
    UCHAR                   Contents[PSAV_READ_BUFFER_SIZE];
} PSAV_NOTIFICATION, *PPSAV_NOTIFICATION;

typedef struct _PSAV_REPLY {
    FILTER_REPLY_HEADER     Header;
    BOOLEAN                 SafeToOpen;
    UCHAR                   Padding[3];
} PSAV_REPLY, *PPSAV_REPLY;

typedef struct _PSAV_CACHE_ENTRY {
    ULONG64  FileId;    /* 0 = empty slot */
    BOOLEAN  IsSafe;
} PSAV_CACHE_ENTRY, *PPSAV_CACHE_ENTRY;

/* --- New kernel-event structures for \PSAVEventPort --- */

typedef enum _PSAV_EVENT_TYPE {
    PsavEventProcessCreate    = 1,
    PsavEventProcessTerminate = 2,
    PsavEventImageLoad        = 3,
    PsavEventHandleStripped   = 4,   /* ObCallback stripped access rights */
} PSAV_EVENT_TYPE;

typedef struct _PSAV_KERNEL_EVENT {
    FILTER_MESSAGE_HEADER Header;   /* 12 bytes (pack 1: ULONG + ULONGLONG) */
    ULONG  EventType;               /* PSAV_EVENT_TYPE */
    ULONG  ProcessId;
    ULONG  ParentProcessId;
    ULONG  AccessMaskStripped;      /* for PsavEventHandleStripped: which bits removed */
    ULONGLONG ImageBase;            /* for image load */
    WCHAR  ImagePath[512];
    WCHAR  CommandLine[256];
} PSAV_KERNEL_EVENT, *PPSAV_KERNEL_EVENT;

typedef struct _PSAV_KERNEL_EVENT_REPLY {
    FILTER_REPLY_HEADER Header;    /* 12 bytes */
    ULONG Acknowledged;            /* always 1 */
} PSAV_KERNEL_EVENT_REPLY, *PPSAV_KERNEL_EVENT_REPLY;

#pragma pack(pop)

/* -----------------------------------------------------------------------
   Module globals
   --------------------------------------------------------------------- */
#define PSAV_CACHE_BUCKETS  1024U

/* Scan port (existing) */
static PFLT_FILTER          g_FilterHandle       = NULL;
static PFLT_PORT            g_ServerPort         = NULL;
static PFLT_PORT            g_ClientPort         = NULL;  /* one client at a time */
static FAST_MUTEX           g_ClientPortLock;

/* Event port (new) */
static PFLT_PORT            g_EventServerPort    = NULL;
static PFLT_PORT            g_EventClientPort    = NULL;
static FAST_MUTEX           g_EventClientPortLock;

/* ObCallback registration handle */
static PVOID                g_ObCallbackHandle   = NULL;

/* Flat file-ID cache (non-paged pool, allocated in DriverEntry) */
static PPSAV_CACHE_ENTRY    g_Cache              = NULL;
static EX_PUSH_LOCK         g_CacheLock;

/* Extensions we never scan */
static const UNICODE_STRING g_SkipExtensions[] = {
    RTL_CONSTANT_STRING(L"lnk"),
    RTL_CONSTANT_STRING(L"tmp"),
    RTL_CONSTANT_STRING(L"log"),
    RTL_CONSTANT_STRING(L"etl"),
    RTL_CONSTANT_STRING(L"evtx"),
    RTL_CONSTANT_STRING(L"mui"),
    RTL_CONSTANT_STRING(L"cat"),
    RTL_CONSTANT_STRING(L"manifest"),
    RTL_CONSTANT_STRING(L"mum"),
};

/* -----------------------------------------------------------------------
   Forward declarations
   --------------------------------------------------------------------- */
DRIVER_UNLOAD PsavDriverUnload;   /* not used directly — see FilterUnload */

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PsavUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PsavPortConnect(
    _In_  PFLT_PORT       ClientPort,
    _In_  PVOID           ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_  ULONG           SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
PsavPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PsavEventPortConnect(
    _In_  PFLT_PORT       ClientPort,
    _In_  PVOID           ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_  ULONG           SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
PsavEventPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
    );

FLT_PREOP_CALLBACK_STATUS
PsavPreCreate(
    _Inout_                        PFLT_CALLBACK_DATA    Data,
    _In_                           PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_  PVOID                *CompletionContext
    );

VOID
PsavProcessNotifyCallbackEx(
    _Inout_     PEPROCESS              Process,
    _In_        HANDLE                 ProcessId,
    _In_opt_    PPS_CREATE_NOTIFY_INFO CreateInfo
    );

VOID
PsavLoadImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo
    );

OB_PREOP_CALLBACK_STATUS
PsavObPreOperationCallback(
    _In_ PVOID                          RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

/* -----------------------------------------------------------------------
   Filter registration
   --------------------------------------------------------------------- */
static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        PsavPreCreate,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                                          /* Flags */
    NULL,                                       /* ContextRegistration */
    g_Callbacks,
    PsavUnload,
    NULL,                                       /* InstanceSetup */
    NULL,                                       /* InstanceQueryTeardown */
    NULL,                                       /* InstanceTeardownStart */
    NULL,                                       /* InstanceTeardownComplete */
    NULL, NULL, NULL                            /* NameProvider callbacks */
};

/* -----------------------------------------------------------------------
   Cache helpers
   --------------------------------------------------------------------- */

_IRQL_requires_max_(APC_LEVEL)
static VOID
PsavCacheLookup(
    _In_  ULONG64  FileId,
    _Out_ PBOOLEAN Found,
    _Out_ PBOOLEAN IsSafe
    )
{
    ULONG bucket = (ULONG)(FileId % PSAV_CACHE_BUCKETS);

    *Found  = FALSE;
    *IsSafe = FALSE;

    if (FileId == 0 || g_Cache == NULL) {
        return;
    }

    FltAcquirePushLockShared(&g_CacheLock);
    if (g_Cache[bucket].FileId == FileId) {
        *Found  = TRUE;
        *IsSafe = g_Cache[bucket].IsSafe;
    }
    FltReleasePushLock(&g_CacheLock);
}

_IRQL_requires_max_(APC_LEVEL)
static VOID
PsavCacheInsert(
    _In_ ULONG64  FileId,
    _In_ BOOLEAN  IsSafe
    )
{
    ULONG bucket;

    if (FileId == 0 || g_Cache == NULL) {
        return;
    }

    bucket = (ULONG)(FileId % PSAV_CACHE_BUCKETS);

    FltAcquirePushLockExclusive(&g_CacheLock);
    g_Cache[bucket].FileId = FileId;
    g_Cache[bucket].IsSafe = IsSafe;
    FltReleasePushLock(&g_CacheLock);
}

/* -----------------------------------------------------------------------
   Extension filter helper
   --------------------------------------------------------------------- */

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
PsavShouldSkipExtension(
    _In_ PUNICODE_STRING Extension
    )
{
    ULONG i;
    for (i = 0; i < ARRAYSIZE(g_SkipExtensions); i++) {
        if (RtlEqualUnicodeString(Extension, &g_SkipExtensions[i], TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
   PsavSendKernelEvent  —  helper to fire-and-forget an event to user mode
   Runs at PASSIVE_LEVEL or APC_LEVEL (kernel callbacks are in that range).
   Uses a 500 ms timeout so a non-listening client doesn't stall the kernel.
   --------------------------------------------------------------------- */
_IRQL_requires_max_(APC_LEVEL)
static VOID
PsavSendKernelEvent(
    _In_ PPSAV_KERNEL_EVENT Event
    )
{
    NTSTATUS                 status;
    PFLT_PORT                eventPort;
    PSAV_KERNEL_EVENT_REPLY  reply     = {0};
    ULONG                    replyLen  = sizeof(PSAV_KERNEL_EVENT_REPLY);
    LARGE_INTEGER            timeout;

    /* 500 ms in negative 100-ns units */
    timeout.QuadPart = -5000000LL;

    ExAcquireFastMutex(&g_EventClientPortLock);
    eventPort = g_EventClientPort;
    ExReleaseFastMutex(&g_EventClientPortLock);

    if (eventPort == NULL) {
        return;
    }

    status = FltSendMessage(
                g_FilterHandle,
                &eventPort,
                Event,
                sizeof(PSAV_KERNEL_EVENT),
                &reply,
                &replyLen,
                &timeout);

    /* Intentionally ignore return value — fire-and-forget. */
    UNREFERENCED_PARAMETER(status);
}

/* -----------------------------------------------------------------------
   DriverEntry
   --------------------------------------------------------------------- */
_Use_decl_annotations_
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS                  status;
    UNICODE_STRING            portName;
    OBJECT_ATTRIBUTES         oa;
    PSECURITY_DESCRIPTOR      sd                = NULL;
    OB_OPERATION_REGISTRATION obOps             = {0};
    OB_CALLBACK_REGISTRATION  obReg             = {0};
    UNICODE_STRING            obAltitude;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* Allocate and zero the file-ID cache from non-paged pool */
    g_Cache = (PPSAV_CACHE_ENTRY)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    sizeof(PSAV_CACHE_ENTRY) * PSAV_CACHE_BUCKETS,
                    PSAV_POOL_TAG);
    if (g_Cache == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* ExAllocatePool2 zero-initialises the memory */

    FltInitializePushLock(&g_CacheLock);
    ExInitializeFastMutex(&g_ClientPortLock);
    ExInitializeFastMutex(&g_EventClientPortLock);

    /* Register the minifilter */
    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_Cache, PSAV_POOL_TAG);
        g_Cache = NULL;
        return status;
    }

    /* ----------------------------------------------------------------
       Create \PSAVScanPort  (existing file-scan port)
       ---------------------------------------------------------------- */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    RtlInitUnicodeString(&portName, L"\\PSAVScanPort");
    InitializeObjectAttributes(&oa,
                               &portName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               sd);

    status = FltCreateCommunicationPort(
                    g_FilterHandle,
                    &g_ServerPort,
                    &oa,
                    NULL,               /* ServerPortCookie */
                    PsavPortConnect,
                    PsavPortDisconnect,
                    NULL,               /* MessageNotify */
                    1                   /* MaxConnections */
                    );

    FltFreeSecurityDescriptor(sd);
    sd = NULL;

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    /* ----------------------------------------------------------------
       Create \PSAVEventPort  (new asynchronous event-streaming port)
       INF AddReg note: add a second string value "EventPortName" = "\PSAVEventPort"
       under HKLM\SYSTEM\CurrentControlSet\Services\PerSourceAntivirus.Driver\Parameters
       ---------------------------------------------------------------- */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    RtlInitUnicodeString(&portName, L"\\PSAVEventPort");
    InitializeObjectAttributes(&oa,
                               &portName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               sd);

    status = FltCreateCommunicationPort(
                    g_FilterHandle,
                    &g_EventServerPort,
                    &oa,
                    NULL,                   /* ServerPortCookie */
                    PsavEventPortConnect,
                    PsavEventPortDisconnect,
                    NULL,                   /* MessageNotify */
                    1                       /* MaxConnections */
                    );

    FltFreeSecurityDescriptor(sd);
    sd = NULL;

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    /* ----------------------------------------------------------------
       Begin intercepting I/O
       ---------------------------------------------------------------- */
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    /* ----------------------------------------------------------------
       Register process-creation notify routine (Ex variant)
       ---------------------------------------------------------------- */
    status = PsSetCreateProcessNotifyRoutineEx(PsavProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    /* ----------------------------------------------------------------
       Register image-load notify routine
       ---------------------------------------------------------------- */
    status = PsSetLoadImageNotifyRoutine(PsavLoadImageNotifyCallback);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(PsavProcessNotifyCallbackEx, TRUE);
        goto Cleanup;
    }

    /* ----------------------------------------------------------------
       Register ObCallback to strip injection-capable access rights
       Altitude must match the minifilter altitude (325000).
       ---------------------------------------------------------------- */
    RtlInitUnicodeString(&obAltitude, L"325000");

    obOps.ObjectType         = PsProcessType;
    obOps.Operations         = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obOps.PreOperation       = PsavObPreOperationCallback;
    obOps.PostOperation      = NULL;

    obReg.Version            = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 1;
    obReg.Altitude           = obAltitude;
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = &obOps;

    status = ObRegisterCallbacks(&obReg, &g_ObCallbackHandle);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(PsavProcessNotifyCallbackEx, TRUE);
        PsSetLoadImageNotifyRoutine(PsavLoadImageNotifyCallback);
        goto Cleanup;
    }

    return STATUS_SUCCESS;

Cleanup:
    if (g_EventServerPort != NULL) {
        FltCloseCommunicationPort(g_EventServerPort);
        g_EventServerPort = NULL;
    }
    if (g_ServerPort != NULL) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }
    FltUnregisterFilter(g_FilterHandle);
    g_FilterHandle = NULL;
    ExFreePoolWithTag(g_Cache, PSAV_POOL_TAG);
    g_Cache = NULL;
    return status;
}

/* -----------------------------------------------------------------------
   PsavUnload
   --------------------------------------------------------------------- */
_Use_decl_annotations_
NTSTATUS
PsavUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    /* Unregister kernel callbacks before closing ports */
    PsSetCreateProcessNotifyRoutineEx(PsavProcessNotifyCallbackEx, TRUE);
    PsSetLoadImageNotifyRoutine(PsavLoadImageNotifyCallback);

    if (g_ObCallbackHandle != NULL) {
        ObUnRegisterCallbacks(g_ObCallbackHandle);
        g_ObCallbackHandle = NULL;
    }

    /* Close event port first, then scan port */
    if (g_EventServerPort != NULL) {
        FltCloseCommunicationPort(g_EventServerPort);
        g_EventServerPort = NULL;
    }

    if (g_ServerPort != NULL) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }

    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    if (g_Cache != NULL) {
        ExFreePoolWithTag(g_Cache, PSAV_POOL_TAG);
        g_Cache = NULL;
    }

    FltDeletePushLock(&g_CacheLock);

    return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
   Scan port connect / disconnect  (existing)
   --------------------------------------------------------------------- */
_Use_decl_annotations_
NTSTATUS
PsavPortConnect(
    _In_  PFLT_PORT ClientPort,
    _In_  PVOID     ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_  ULONG     SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    *ConnectionPortCookie = NULL;

    ExAcquireFastMutex(&g_ClientPortLock);
    g_ClientPort = ClientPort;
    ExReleaseFastMutex(&g_ClientPortLock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PsavPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    ExAcquireFastMutex(&g_ClientPortLock);
    if (g_ClientPort != NULL) {
        FltCloseClientPort(g_FilterHandle, &g_ClientPort);
        g_ClientPort = NULL;
    }
    ExReleaseFastMutex(&g_ClientPortLock);
}

/* -----------------------------------------------------------------------
   Event port connect / disconnect  (new)
   --------------------------------------------------------------------- */
_Use_decl_annotations_
NTSTATUS
PsavEventPortConnect(
    _In_  PFLT_PORT ClientPort,
    _In_  PVOID     ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_  ULONG     SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    *ConnectionPortCookie = NULL;

    ExAcquireFastMutex(&g_EventClientPortLock);
    g_EventClientPort = ClientPort;
    ExReleaseFastMutex(&g_EventClientPortLock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PsavEventPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    ExAcquireFastMutex(&g_EventClientPortLock);
    if (g_EventClientPort != NULL) {
        FltCloseClientPort(g_FilterHandle, &g_EventClientPort);
        g_EventClientPort = NULL;
    }
    ExReleaseFastMutex(&g_EventClientPortLock);
}

/* -----------------------------------------------------------------------
   PsavProcessNotifyCallbackEx
   Registered with PsSetCreateProcessNotifyRoutineEx.
   CreateInfo != NULL  => process is being created.
   CreateInfo == NULL  => process is terminating.
   Runs at PASSIVE_LEVEL.
   --------------------------------------------------------------------- */
_Use_decl_annotations_
VOID
PsavProcessNotifyCallbackEx(
    _Inout_     PEPROCESS              Process,
    _In_        HANDLE                 ProcessId,
    _In_opt_    PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    PSAV_KERNEL_EVENT evt = {0};

    UNREFERENCED_PARAMETER(Process);

    evt.ProcessId = HandleToULong(ProcessId);

    if (CreateInfo != NULL) {
        /* Process create */
        evt.EventType        = PsavEventProcessCreate;
        evt.ParentProcessId  = HandleToULong(CreateInfo->ParentProcessId);

        /* Copy image path (ImageFileName may be NULL for early system processes) */
        if (CreateInfo->ImageFileName != NULL &&
            CreateInfo->ImageFileName->Length > 0 &&
            CreateInfo->ImageFileName->Buffer != NULL)
        {
            USHORT copyChars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
            if (copyChars >= ARRAYSIZE(evt.ImagePath)) {
                copyChars = ARRAYSIZE(evt.ImagePath) - 1;
            }
            RtlCopyMemory(evt.ImagePath,
                          CreateInfo->ImageFileName->Buffer,
                          copyChars * sizeof(WCHAR));
            /* remaining chars are zero from zero-init of evt */
        }

        /* Copy command line (CommandLine may be NULL) */
        if (CreateInfo->CommandLine != NULL &&
            CreateInfo->CommandLine->Length > 0 &&
            CreateInfo->CommandLine->Buffer != NULL)
        {
            USHORT copyChars = CreateInfo->CommandLine->Length / sizeof(WCHAR);
            if (copyChars >= ARRAYSIZE(evt.CommandLine)) {
                copyChars = ARRAYSIZE(evt.CommandLine) - 1;
            }
            RtlCopyMemory(evt.CommandLine,
                          CreateInfo->CommandLine->Buffer,
                          copyChars * sizeof(WCHAR));
        }
    } else {
        /* Process terminate */
        evt.EventType = PsavEventProcessTerminate;
    }

    PsavSendKernelEvent(&evt);
}

/* -----------------------------------------------------------------------
   PsavLoadImageNotifyCallback
   Registered with PsSetLoadImageNotifyRoutine.
   Fires whenever a DLL or EXE image is mapped into a process.
   Runs at PASSIVE_LEVEL or APC_LEVEL.
   --------------------------------------------------------------------- */
_Use_decl_annotations_
VOID
PsavLoadImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo
    )
{
    PSAV_KERNEL_EVENT evt = {0};

    evt.EventType  = PsavEventImageLoad;
    evt.ProcessId  = HandleToULong(ProcessId);
    evt.ImageBase  = (ULONGLONG)(ULONG_PTR)ImageInfo->ImageBase;

    if (FullImageName != NULL &&
        FullImageName->Length > 0 &&
        FullImageName->Buffer != NULL)
    {
        USHORT copyChars = FullImageName->Length / sizeof(WCHAR);
        if (copyChars >= ARRAYSIZE(evt.ImagePath)) {
            copyChars = ARRAYSIZE(evt.ImagePath) - 1;
        }
        RtlCopyMemory(evt.ImagePath,
                      FullImageName->Buffer,
                      copyChars * sizeof(WCHAR));
    }

    PsavSendKernelEvent(&evt);
}

/* -----------------------------------------------------------------------
   PsavObPreOperationCallback
   Registered via ObRegisterCallbacks for process objects.
   Strips PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION
   from any handle-open/duplicate that would grant injection capability.
   Returns OB_PREOP_SUCCESS (mandatory).
   --------------------------------------------------------------------- */
_Use_decl_annotations_
OB_PREOP_CALLBACK_STATUS
PsavObPreOperationCallback(
    _In_    PVOID                            RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION    OperationInformation
    )
{
#define PSAV_INJECT_MASK  (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION)

    ACCESS_MASK desired;
    ACCESS_MASK stripped;

    UNREFERENCED_PARAMETER(RegistrationContext);

    /* Only strip on handle-create operations */
    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE &&
        OperationInformation->Operation != OB_OPERATION_HANDLE_DUPLICATE) {
        return OB_PREOP_SUCCESS;
    }

    desired = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

    /* Check if any injection-capable bits are requested */
    if ((desired & PSAV_INJECT_MASK) == 0) {
        return OB_PREOP_SUCCESS;
    }

    /* Strip the dangerous bits */
    stripped = desired & PSAV_INJECT_MASK;
    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PSAV_INJECT_MASK;

    /* Send a stripped-access event to user mode */
    {
        PSAV_KERNEL_EVENT evt = {0};
        HANDLE            targetPid;

        evt.EventType         = PsavEventHandleStripped;
        evt.AccessMaskStripped = stripped;

        /* Identify the target process */
        targetPid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
        evt.ProcessId = HandleToULong(targetPid);

        PsavSendKernelEvent(&evt);
    }

    return OB_PREOP_SUCCESS;

#undef PSAV_INJECT_MASK
}

/* -----------------------------------------------------------------------
   PsavPreCreate  —  main interception callback  (unchanged)
   --------------------------------------------------------------------- */
_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS
PsavPreCreate(
    _Inout_                        PFLT_CALLBACK_DATA    Data,
    _In_                           PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_  PVOID                *CompletionContext
    )
{
    NTSTATUS                    status;
    PFLT_FILE_NAME_INFORMATION  nameInfo       = NULL;
    PPSAV_NOTIFICATION          notification   = NULL;
    HANDLE                      fileHandle     = INVALID_HANDLE_VALUE;
    PFILE_OBJECT                fileObject     = NULL;
    PFLT_PORT                   clientPort     = NULL;
    OBJECT_ATTRIBUTES           oa;
    IO_STATUS_BLOCK             iosb;
    LARGE_INTEGER               byteOffset;
    ULONG                       bytesRead      = 0;
    FILE_INTERNAL_INFORMATION   fileIdInfo     = {0};
    BOOLEAN                     found, isSafe;
    PSAV_REPLY                  reply          = {0};
    ULONG                       replyLength    = sizeof(PSAV_REPLY);
    LARGE_INTEGER               timeout;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* 1. Skip kernel-mode requestors */
    if (FLT_IS_IRP_OPERATION(Data) &&
        Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 2. Only handle user-mode file creates/opens */
    if (!FLT_IS_IRP_OPERATION(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 3. Skip if no user-mode client is connected (fail-open) */
    ExAcquireFastMutex(&g_ClientPortLock);
    clientPort = g_ClientPort;
    ExReleaseFastMutex(&g_ClientPortLock);

    if (clientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 4. Get file name information */
    status = FltGetFileNameInformation(
                    Data,
                    FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                    &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 5. Skip uninteresting extensions */
    if (nameInfo->Extension.Length > 0 &&
        PsavShouldSkipExtension(&nameInfo->Extension)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 6. Open the file to read its content and obtain its FileId.
          Use FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY so we don't recurse
          into our own pre-create, and pass IO_NO_PARAMETER_CHECKING /
          IO_FORCE_ACCESS_CHECK appropriately. */
    InitializeObjectAttributes(&oa,
                               &nameInfo->Name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    status = FltCreateFileEx(
                    FltObjects->Filter,
                    FltObjects->Instance,
                    &fileHandle,
                    &fileObject,
                    GENERIC_READ | SYNCHRONIZE,
                    &oa,
                    &iosb,
                    NULL,                         /* AllocationSize */
                    FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE |
                        FILE_SYNCHRONOUS_IO_NONALERT,
                    NULL, 0,
                    IO_IGNORE_SHARE_ACCESS_CHECK);

    if (!NT_SUCCESS(status)) {
        /* File may not exist yet or is a directory — let it through */
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 7. Query NTFS FileId */
    status = FltQueryInformationFile(
                    FltObjects->Instance,
                    fileObject,
                    &fileIdInfo,
                    sizeof(FILE_INTERNAL_INFORMATION),
                    FileInternalInformation,
                    NULL);

    if (NT_SUCCESS(status) && fileIdInfo.IndexNumber.QuadPart != 0) {
        ULONG64 fileId = (ULONG64)fileIdInfo.IndexNumber.QuadPart;

        PsavCacheLookup(fileId, &found, &isSafe);

        if (found) {
            FltClose(fileHandle);
            ObDereferenceObject(fileObject);
            FltReleaseFileNameInformation(nameInfo);

            if (!isSafe) {
                Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    /* 8. Allocate notification buffer (non-paged, zero-initialised) */
    notification = (PPSAV_NOTIFICATION)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED,
                        sizeof(PSAV_NOTIFICATION),
                        PSAV_POOL_TAG);
    if (notification == NULL) {
        FltClose(fileHandle);
        ObDereferenceObject(fileObject);
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;   /* fail-open */
    }

    /* 9. Copy file name (truncate safely) */
    {
        ULONG copyBytes = nameInfo->Name.Length;
        if (copyBytes > (PSAV_FILENAME_MAX - 1) * sizeof(WCHAR)) {
            copyBytes = (PSAV_FILENAME_MAX - 1) * sizeof(WCHAR);
        }
        RtlCopyMemory(notification->FileName, nameInfo->Name.Buffer, copyBytes);
        /* remaining chars are already zero from ExAllocatePool2 */
    }

    /* 10. Read first PSAV_READ_BUFFER_SIZE bytes */
    byteOffset.QuadPart = 0;
    status = FltReadFile(
                    FltObjects->Instance,
                    fileObject,
                    &byteOffset,
                    PSAV_READ_BUFFER_SIZE,
                    notification->Contents,
                    FLTFL_IO_OPERATION_NON_CACHED |
                        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                    &bytesRead,
                    NULL,
                    NULL);

    if (!NT_SUCCESS(status) && status != STATUS_END_OF_FILE) {
        bytesRead = 0;
    }
    notification->BytesToScan = bytesRead;
    notification->Flags       = 0;

    FltClose(fileHandle);
    ObDereferenceObject(fileObject);
    fileObject = NULL;
    fileHandle = INVALID_HANDLE_VALUE;

    /* 11. Send message to user mode; 3-second timeout */
    timeout.QuadPart = -3LL * 10000000LL;   /* 3 s in 100-ns intervals */

    ExAcquireFastMutex(&g_ClientPortLock);
    clientPort = g_ClientPort;
    ExReleaseFastMutex(&g_ClientPortLock);

    if (clientPort == NULL) {
        /* Disconnected between check and send — fail-open */
        ExFreePoolWithTag(notification, PSAV_POOL_TAG);
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltSendMessage(
                    g_FilterHandle,
                    &clientPort,
                    notification,
                    sizeof(PSAV_NOTIFICATION),
                    &reply,
                    &replyLength,
                    &timeout);

    ExFreePoolWithTag(notification, PSAV_POOL_TAG);
    FltReleaseFileNameInformation(nameInfo);

    /* 12. Evaluate reply */
    if (status == STATUS_SUCCESS && replyLength >= sizeof(PSAV_REPLY)) {

        BOOLEAN safe = reply.SafeToOpen;

        /* Update cache with the verdict */
        if (fileIdInfo.IndexNumber.QuadPart != 0) {
            PsavCacheInsert((ULONG64)fileIdInfo.IndexNumber.QuadPart, safe);
        }

        if (!safe) {
            Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

    }
    /* On timeout (STATUS_TIMEOUT), port error, or any other failure: fail-open */

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
