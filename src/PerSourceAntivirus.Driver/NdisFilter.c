/*++
Module Name:
    NdisFilter.c

Abstract:
    NDIS 6.x Lightweight Filter (LWF) driver for PerSourceAntivirus.
    Inspects inbound/outbound network packets for known exploit signatures:
      - EternalBlue  (MS17-010): SMBv1 TRANS2 on port 445
      - Log4Shell    (CVE-2021-44228): JNDI injection in HTTP payloads
      - Heartbleed   (CVE-2014-0160): Oversized TLS heartbeat
      - BlueKeep     (CVE-2019-0708): RDP pre-auth exploit pattern

    Events are written to a shared memory section \BaseNamedObjects\PSAVNdisEvents
    for consumption by the user-mode C# service.

Environment:
    Kernel mode only. Requires WDK 10.0.26100+.
    Build separately: not part of the minifilter CMakeLists target.

Filter service name : PSAVNdisFilter
Filter friendly name: PerSourceAntivirus Network Filter
Filter altitude     : 320000 (FSFilter Anti-Virus range)
--*/

#include <ndis.h>
#include <wdm.h>

#pragma warning(disable: 4100)  /* unreferenced formal parameter */

/* -----------------------------------------------------------------------
   Constants
   --------------------------------------------------------------------- */
#define PSAV_NDIS_POOL_TAG          'DNAV'
#define PSAV_NDIS_MAJOR_VERSION     6
#define PSAV_NDIS_MINOR_VERSION     30
#define PSAV_EVENT_RING_SIZE        256
#define PSAV_PAYLOAD_SNAPSHOT       128  /* bytes captured per event */
#define PSAV_FILTER_VERSION         ((PSAV_NDIS_MAJOR_VERSION << 8) | PSAV_NDIS_MINOR_VERSION)

/* -----------------------------------------------------------------------
   Shared event ring buffer (mapped to \BaseNamedObjects\PSAVNdisEvents)
   --------------------------------------------------------------------- */
#pragma pack(push, 1)

typedef enum _PSAV_NET_SIGNATURE {
    PsavNetSigNone        = 0,
    PsavNetSigEternalBlue = 1,
    PsavNetSigLog4Shell   = 2,
    PsavNetSigHeartbleed  = 3,
    PsavNetSigBlueKeep    = 4,
} PSAV_NET_SIGNATURE;

typedef struct _PSAV_NET_EVENT {
    ULONG     Signature;        /* PSAV_NET_SIGNATURE */
    ULONG     SrcIpv4;          /* source IPv4, host byte order */
    ULONG     DstIpv4;          /* dest IPv4, host byte order */
    USHORT    SrcPort;
    USHORT    DstPort;
    USHORT    PayloadLength;    /* length of snapshot below */
    USHORT    Reserved;
    UCHAR     Payload[PSAV_PAYLOAD_SNAPSHOT];
    LARGE_INTEGER Timestamp;   /* KeQuerySystemTime */
} PSAV_NET_EVENT, *PPSAV_NET_EVENT;

typedef struct _PSAV_NDIS_SHARED {
    ULONG          WriteIndex;  /* producer index (mod RING_SIZE) */
    ULONG          ReadIndex;   /* consumer index (mod RING_SIZE) */
    PSAV_NET_EVENT Ring[PSAV_EVENT_RING_SIZE];
} PSAV_NDIS_SHARED, *PPSAV_NDIS_SHARED;

#pragma pack(pop)

/* -----------------------------------------------------------------------
   Filter context
   --------------------------------------------------------------------- */
typedef struct _PSAV_FILTER_CONTEXT {
    LIST_ENTRY          ListEntry;
    NDIS_HANDLE         FilterHandle;
    NDIS_HANDLE         NdisFilterHandle;
    BOOLEAN             Running;
} PSAV_FILTER_CONTEXT, *PPSAV_FILTER_CONTEXT;

/* -----------------------------------------------------------------------
   Globals
   --------------------------------------------------------------------- */
static NDIS_HANDLE          g_FilterDriverHandle = NULL;
static LIST_ENTRY           g_FilterList;
static NDIS_SPIN_LOCK       g_FilterListLock;

/* Shared memory for user-mode consumption */
static PMDL                 g_SharedMdl     = NULL;
static PPSAV_NDIS_SHARED    g_Shared        = NULL;
static NDIS_SPIN_LOCK       g_SharedLock;

/* -----------------------------------------------------------------------
   Forward declarations
   --------------------------------------------------------------------- */
DRIVER_UNLOAD PsavNdisDriverUnload;

FILTER_ATTACH               PsavNdisAttach;
FILTER_DETACH               PsavNdisDetach;
FILTER_PAUSE                PsavNdisPause;
FILTER_RESTART              PsavNdisRestart;
FILTER_SEND_NET_BUFFER_LISTS          PsavNdisSendNetBufferLists;
FILTER_SEND_NET_BUFFER_LISTS_COMPLETE PsavNdisSendNetBufferListsComplete;
FILTER_RECEIVE_NET_BUFFER_LISTS       PsavNdisReceiveNetBufferLists;
FILTER_RETURN_NET_BUFFER_LISTS        PsavNdisReturnNetBufferLists;
FILTER_SET_MODULE_OPTIONS             PsavNdisSetModuleOptions;
FILTER_OID_REQUEST                    PsavNdisOidRequest;
FILTER_OID_REQUEST_COMPLETE           PsavNdisOidRequestComplete;
FILTER_STATUS                         PsavNdisStatus;
FILTER_NET_PNP_EVENT                  PsavNdisNetPnPEvent;
FILTER_CANCEL_SEND_NET_BUFFER_LISTS   PsavNdisCancelSend;

/* -----------------------------------------------------------------------
   Signature scanning helpers
   --------------------------------------------------------------------- */
_IRQL_requires_max_(DISPATCH_LEVEL)
static PSAV_NET_SIGNATURE
PsavNdisScanPayload(
    _In_reads_bytes_(Length) const UCHAR *Payload,
    _In_ ULONG Length,
    _In_ USHORT SrcPort,
    _In_ USHORT DstPort
    )
{
    /* EternalBlue: SMBv1 header \xFF SMB on port 445 */
    if ((SrcPort == 445 || DstPort == 445) && Length >= 5) {
        for (ULONG i = 0; i + 4 < Length; i++) {
            if (Payload[i] == 0xFF &&
                Payload[i+1] == 0x53 &&
                Payload[i+2] == 0x4D &&
                Payload[i+3] == 0x42) {
                return PsavNetSigEternalBlue;
            }
        }
    }

    /* Log4Shell: "${jndi:" in HTTP payloads */
    if ((DstPort == 80 || DstPort == 8080 || DstPort == 443 || DstPort == 8443) && Length > 7) {
        static const UCHAR jndi[] = { '$', '{', 'j', 'n', 'd', 'i', ':' };
        for (ULONG i = 0; i + 7 <= Length; i++) {
            BOOLEAN match = TRUE;
            for (ULONG j = 0; j < 7; j++) {
                /* Case-insensitive compare for ASCII letters */
                UCHAR a = Payload[i+j];
                UCHAR b = jndi[j];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (a != b) { match = FALSE; break; }
            }
            if (match) return PsavNetSigLog4Shell;
        }
    }

    /* Heartbleed: TLS Heartbeat record type 0x18 with oversized payload */
    if ((SrcPort == 443 || DstPort == 443) && Length >= 7) {
        if (Payload[0] == 0x18) {  /* TLS heartbeat record */
            USHORT hbLen = (USHORT)((Payload[5] << 8) | Payload[6]);
            if (hbLen > 16384) return PsavNetSigHeartbleed;
        }
    }

    /* BlueKeep: TPKT + COTP CR on RDP port 3389 */
    if ((SrcPort == 3389 || DstPort == 3389) && Length >= 11) {
        if (Payload[0] == 0x03 && Payload[1] == 0x00 && Payload[4] == 0xE0) {
            /* Check for "Microsof" or "mstshash=" cookie */
            for (ULONG i = 5; i + 8 <= Length; i++) {
                if (Payload[i]   == 'M' && Payload[i+1] == 'i' &&
                    Payload[i+2] == 'c' && Payload[i+3] == 'r' &&
                    Payload[i+4] == 'o' && Payload[i+5] == 's' &&
                    Payload[i+6] == 'o' && Payload[i+7] == 'f') {
                    return PsavNetSigBlueKeep;
                }
            }
        }
    }

    return PsavNetSigNone;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
PsavNdisPublishEvent(
    _In_ PSAV_NET_SIGNATURE Sig,
    _In_ ULONG SrcIpv4,
    _In_ ULONG DstIpv4,
    _In_ USHORT SrcPort,
    _In_ USHORT DstPort,
    _In_reads_bytes_(PayLen) const UCHAR *Payload,
    _In_ USHORT PayLen
    )
{
    PSAV_NET_EVENT *entry;
    ULONG           writeIdx;

    if (g_Shared == NULL) return;

    NdisAcquireSpinLock(&g_SharedLock);

    writeIdx = g_Shared->WriteIndex % PSAV_EVENT_RING_SIZE;
    entry = &g_Shared->Ring[writeIdx];

    entry->Signature   = (ULONG)Sig;
    entry->SrcIpv4     = SrcIpv4;
    entry->DstIpv4     = DstIpv4;
    entry->SrcPort     = SrcPort;
    entry->DstPort     = DstPort;
    entry->PayloadLength = PayLen < PSAV_PAYLOAD_SNAPSHOT ? PayLen : PSAV_PAYLOAD_SNAPSHOT;
    RtlCopyMemory(entry->Payload, Payload, entry->PayloadLength);
    KeQuerySystemTime(&entry->Timestamp);

    g_Shared->WriteIndex = (writeIdx + 1) % PSAV_EVENT_RING_SIZE;

    NdisReleaseSpinLock(&g_SharedLock);
}

/* -----------------------------------------------------------------------
   Inspect a chain of NET_BUFFER_LISTs for exploit signatures
   --------------------------------------------------------------------- */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
PsavNdisInspectNblChain(
    _In_ PNET_BUFFER_LIST NblChain
    )
{
    PNET_BUFFER_LIST nbl;
    PNET_BUFFER      nb;

    for (nbl = NblChain; nbl != NULL; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {
        for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
            ULONG dataLen = NET_BUFFER_DATA_LENGTH(nb);
            if (dataLen < 40) continue;  /* too small for any IP header + TCP */

            /* Get a contiguous view into the packet data.
               NdisGetDataBuffer copies into scratch if needed. */
            UCHAR scratch[256];
            ULONG viewLen = dataLen < sizeof(scratch) ? dataLen : sizeof(scratch);
            PUCHAR data = NdisGetDataBuffer(nb, viewLen, scratch, 1, 0);
            if (data == NULL) continue;

            /* Minimal Ethernet + IPv4 + TCP parsing */
            /* Skip Ethernet header (14 bytes) */
            if (viewLen < 14 + 20 + 4) continue;
            PUCHAR ipHdr = data + 14;

            /* Check EtherType = 0x0800 (IPv4) */
            if (data[12] != 0x08 || data[13] != 0x00) continue;

            UCHAR  protocol = ipHdr[9];
            if (protocol != 6) continue;  /* TCP only */

            ULONG  srcIpv4 = (ipHdr[12] << 24) | (ipHdr[13] << 16) | (ipHdr[14] << 8) | ipHdr[15];
            ULONG  dstIpv4 = (ipHdr[16] << 24) | (ipHdr[17] << 16) | (ipHdr[18] << 8) | ipHdr[19];

            UCHAR  ipHdrLen = (ipHdr[0] & 0x0F) * 4;
            if (viewLen < 14 + (ULONG)ipHdrLen + 4) continue;

            PUCHAR tcpHdr  = ipHdr + ipHdrLen;
            USHORT srcPort = (USHORT)((tcpHdr[0] << 8) | tcpHdr[1]);
            USHORT dstPort = (USHORT)((tcpHdr[2] << 8) | tcpHdr[3]);
            UCHAR  tcpHdrLen = ((tcpHdr[12] >> 4) & 0x0F) * 4;

            PUCHAR payload = tcpHdr + tcpHdrLen;
            ULONG  payLen  = 0;
            {
                ULONG offset = (ULONG)(payload - data);
                if (offset < viewLen)
                    payLen = viewLen - offset;
            }
            if (payLen < 4) continue;

            PSAV_NET_SIGNATURE sig = PsavNdisScanPayload(payload, payLen,
                                                          srcPort, dstPort);
            if (sig != PsavNetSigNone) {
                PsavNdisPublishEvent(sig, srcIpv4, dstIpv4, srcPort, dstPort,
                                     payload, (USHORT)payLen);
            }
        }
    }
}

/* -----------------------------------------------------------------------
   NDIS filter callbacks
   --------------------------------------------------------------------- */
_Use_decl_annotations_
NDIS_STATUS
PsavNdisAttach(
    _In_ NDIS_HANDLE NdisFilterHandle,
    _In_ NDIS_HANDLE FilterDriverContext,
    _In_ PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters
    )
{
    PPSAV_FILTER_CONTEXT ctx;
    NDIS_FILTER_ATTRIBUTES attrs = {0};
    NDIS_STATUS status;

    UNREFERENCED_PARAMETER(FilterDriverContext);
    UNREFERENCED_PARAMETER(AttachParameters);

    ctx = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PSAV_FILTER_CONTEXT), PSAV_NDIS_POOL_TAG);
    if (ctx == NULL) return NDIS_STATUS_RESOURCES;

    RtlZeroMemory(ctx, sizeof(PSAV_FILTER_CONTEXT));
    ctx->FilterHandle = NdisFilterHandle;

    attrs.Header.Type     = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    attrs.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    attrs.Header.Size     = sizeof(NDIS_FILTER_ATTRIBUTES);
    attrs.Flags           = 0;

    status = NdisFSetAttributes(NdisFilterHandle, ctx, &attrs);
    if (status != NDIS_STATUS_SUCCESS) {
        ExFreePoolWithTag(ctx, PSAV_NDIS_POOL_TAG);
        return status;
    }

    NdisAcquireSpinLock(&g_FilterListLock);
    InsertTailList(&g_FilterList, &ctx->ListEntry);
    NdisReleaseSpinLock(&g_FilterListLock);

    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PsavNdisDetach(
    _In_ NDIS_HANDLE FilterModuleContext
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;

    NdisAcquireSpinLock(&g_FilterListLock);
    RemoveEntryList(&ctx->ListEntry);
    NdisReleaseSpinLock(&g_FilterListLock);

    ExFreePoolWithTag(ctx, PSAV_NDIS_POOL_TAG);
}

_Use_decl_annotations_
NDIS_STATUS
PsavNdisPause(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    UNREFERENCED_PARAMETER(PauseParameters);
    ctx->Running = FALSE;
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
NDIS_STATUS
PsavNdisRestart(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    UNREFERENCED_PARAMETER(RestartParameters);
    ctx->Running = TRUE;
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PsavNdisSendNetBufferLists(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ NDIS_PORT_NUMBER PortNumber,
    _In_ ULONG SendFlags
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    if (ctx->Running) PsavNdisInspectNblChain(NetBufferLists);
    NdisFSendNetBufferLists(ctx->FilterHandle, NetBufferLists, PortNumber, SendFlags);
}

_Use_decl_annotations_
VOID
PsavNdisSendNetBufferListsComplete(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ ULONG SendCompleteFlags
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    NdisFSendNetBufferListsComplete(ctx->FilterHandle, NetBufferLists, SendCompleteFlags);
}

_Use_decl_annotations_
VOID
PsavNdisReceiveNetBufferLists(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ NDIS_PORT_NUMBER PortNumber,
    _In_ ULONG NumberOfNetBufferLists,
    _In_ ULONG ReceiveFlags
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    if (ctx->Running) PsavNdisInspectNblChain(NetBufferLists);
    NdisFIndicateReceiveNetBufferLists(ctx->FilterHandle, NetBufferLists,
                                       PortNumber, NumberOfNetBufferLists, ReceiveFlags);
}

_Use_decl_annotations_
VOID
PsavNdisReturnNetBufferLists(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ ULONG ReturnFlags
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    NdisFReturnNetBufferLists(ctx->FilterHandle, NetBufferLists, ReturnFlags);
}

_Use_decl_annotations_
NDIS_STATUS
PsavNdisSetModuleOptions(
    _In_ NDIS_HANDLE FilterModuleContext
    )
{
    UNREFERENCED_PARAMETER(FilterModuleContext);
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
NDIS_STATUS
PsavNdisOidRequest(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_OID_REQUEST OidRequest
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    return NdisFOidRequest(ctx->FilterHandle, OidRequest);
}

_Use_decl_annotations_
VOID
PsavNdisOidRequestComplete(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_OID_REQUEST OidRequest,
    _In_ NDIS_STATUS Status
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    NdisFOidRequestComplete(ctx->FilterHandle, OidRequest, Status);
}

_Use_decl_annotations_
VOID
PsavNdisStatus(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_STATUS_INDICATION StatusIndication
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    NdisFIndicateStatus(ctx->FilterHandle, StatusIndication);
}

_Use_decl_annotations_
NDIS_STATUS
PsavNdisNetPnPEvent(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_PNP_EVENT_NOTIFICATION NetPnPEvent
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    return NdisFNetPnPEvent(ctx->FilterHandle, NetPnPEvent);
}

_Use_decl_annotations_
VOID
PsavNdisCancelSend(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PVOID CancelId
    )
{
    PPSAV_FILTER_CONTEXT ctx = (PPSAV_FILTER_CONTEXT)FilterModuleContext;
    NdisFCancelSendNetBufferLists(ctx->FilterHandle, CancelId);
}

VOID PsavNdisDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    NdisDeregisterFilterDriver(g_FilterDriverHandle);
    if (g_Shared != NULL && g_SharedMdl != NULL) {
        MmUnmapLockedPages(g_Shared, g_SharedMdl);
        MmUnlockPages(g_SharedMdl);
        IoFreeMdl(g_SharedMdl);
    }
}

/* -----------------------------------------------------------------------
   DriverEntry
   --------------------------------------------------------------------- */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NDIS_STATUS                     status;
    NDIS_FILTER_DRIVER_CHARACTERISTICS chars;
    PVOID                           sharedMem;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = PsavNdisDriverUnload;

    /* Initialise list and locks */
    InitializeListHead(&g_FilterList);
    NdisAllocateSpinLock(&g_FilterListLock);
    NdisAllocateSpinLock(&g_SharedLock);

    /* Allocate shared ring buffer (non-paged, non-executable) */
    sharedMem = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PSAV_NDIS_SHARED), PSAV_NDIS_POOL_TAG);
    if (sharedMem != NULL) {
        RtlZeroMemory(sharedMem, sizeof(PSAV_NDIS_SHARED));
        g_SharedMdl = IoAllocateMdl(sharedMem, sizeof(PSAV_NDIS_SHARED), FALSE, FALSE, NULL);
        if (g_SharedMdl != NULL) {
            MmBuildMdlForNonPagedPool(g_SharedMdl);
            g_Shared = (PPSAV_NDIS_SHARED)MmGetSystemAddressForMdlSafe(g_SharedMdl, NormalPagePriority);
        }
    }

    /* Register filter driver */
    RtlZeroMemory(&chars, sizeof(chars));
    chars.Header.Type     = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    chars.Header.Size     = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
    chars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
    chars.MajorNdisVersion = PSAV_NDIS_MAJOR_VERSION;
    chars.MinorNdisVersion = PSAV_NDIS_MINOR_VERSION;
    chars.MajorDriverVersion = 1;
    chars.MinorDriverVersion = 0;
    chars.Flags = 0;

    RtlInitUnicodeString(&chars.ServiceName, L"PSAVNdisFilter");
    RtlInitUnicodeString(&chars.FriendlyName, L"PerSourceAntivirus Network Filter");
    RtlInitUnicodeString(&chars.UniqueName,   L"{B1E22C01-ABCD-4321-AABB-0102030405FF}");

    chars.SetOptionsHandler           = NULL;
    chars.AttachHandler               = PsavNdisAttach;
    chars.DetachHandler               = PsavNdisDetach;
    chars.PauseHandler                = PsavNdisPause;
    chars.RestartHandler              = PsavNdisRestart;
    chars.SendNetBufferListsHandler   = PsavNdisSendNetBufferLists;
    chars.SendNetBufferListsCompleteHandler = PsavNdisSendNetBufferListsComplete;
    chars.ReceiveNetBufferListsHandler = PsavNdisReceiveNetBufferLists;
    chars.ReturnNetBufferListsHandler  = PsavNdisReturnNetBufferLists;
    chars.OidRequestHandler           = PsavNdisOidRequest;
    chars.OidRequestCompleteHandler   = PsavNdisOidRequestComplete;
    chars.StatusHandler               = PsavNdisStatus;
    chars.NetPnPEventHandler          = PsavNdisNetPnPEvent;
    chars.CancelSendNetBufferListsHandler = PsavNdisCancelSend;
    chars.SetModuleOptionsHandler     = PsavNdisSetModuleOptions;

    status = NdisRegisterFilterDriver(DriverObject, DriverObject, &chars, &g_FilterDriverHandle);
    if (status != NDIS_STATUS_SUCCESS) {
        if (sharedMem) ExFreePoolWithTag(sharedMem, PSAV_NDIS_POOL_TAG);
        return status;
    }

    return STATUS_SUCCESS;
}
