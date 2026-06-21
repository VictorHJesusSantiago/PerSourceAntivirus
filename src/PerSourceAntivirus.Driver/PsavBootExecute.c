/*++
Module Name:
    PsavBootExecute.c

Abstract:
    Native boot-execute scanner for PerSourceAntivirus.
    Registered in HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
    as "psavboot" so it runs before the Win32 subsystem initialises.

    Uses only native APIs (ntdll.dll) — no Win32 (kernel32.dll, user32.dll) calls allowed.
    Scans \SystemRoot\System32\ for EXE/DLL files and checks basic PE header integrity.
    Writes findings to \SystemRoot\Temp\PsavBootScan.log.

    Compile with:  cl /nodefaultlib /entry:NtProcessStartup PsavBootExecute.c ntdll.lib
    Output: psavboot.exe — copy to %SystemRoot%\system32\ or use full path in BootExecute.

Environment:
    Native NT environment (no Win32 subsystem, no heap manager at startup).
--*/

/* ---- Native API type definitions (avoid pulling in full WDK) ---- */
typedef long NTSTATUS;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
typedef void *PVOID;
typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR;
typedef const WCHAR *PCWSTR;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef unsigned short WORD;
typedef unsigned long DWORD;

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_NO_MORE_FILES        ((NTSTATUS)0x80000006L)
#define STATUS_END_OF_FILE          ((NTSTATUS)0xC0000011L)
#define OBJ_CASE_INSENSITIVE        0x00000040UL
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020UL
#define FILE_NON_DIRECTORY_FILE     0x00000040UL
#define FILE_DIRECTORY_FILE         0x00000001UL
#define FILE_LIST_DIRECTORY         0x00000001UL
#define SYNCHRONIZE                 0x00100000UL
#define FILE_READ_DATA              0x00000001UL
#define FILE_WRITE_DATA             0x00000002UL
#define FILE_APPEND_DATA            0x00000004UL
#define FILE_GENERIC_READ           (FILE_READ_DATA | SYNCHRONIZE | 0x20080UL)
#define FILE_GENERIC_WRITE          (FILE_WRITE_DATA | FILE_APPEND_DATA | SYNCHRONIZE | 0x20100UL)
#define FILE_SHARE_READ             0x00000001UL
#define FILE_SHARE_WRITE            0x00000002UL
#define FILE_OPEN                   0x00000001UL
#define FILE_CREATE                 0x00000002UL
#define FILE_OVERWRITE_IF           0x00000005UL

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    PVOID           RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONGLONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           FileIndex;
    LONGLONG        CreationTime;
    LONGLONG        LastAccessTime;
    LONGLONG        LastWriteTime;
    LONGLONG        ChangeTime;
    LONGLONG        EndOfFile;
    LONGLONG        AllocationSize;
    ULONG           FileAttributes;
    ULONG           FileNameLength;
    WCHAR           FileName[1];
} FILE_DIRECTORY_INFORMATION;

/* ---- Ntdll imports ---- */
__declspec(dllimport) NTSTATUS __stdcall NtOpenFile(
    PVOID *FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjAttr,
    PIO_STATUS_BLOCK IoStatus, ULONG ShareAccess, ULONG OpenOptions);
__declspec(dllimport) NTSTATUS __stdcall NtQueryDirectoryFile(
    PVOID FileHandle, PVOID Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatus, PVOID FileInfo, ULONG Length,
    int FileInfoClass, int ReturnSingleEntry, PUNICODE_STRING FileName,
    int RestartScan);
__declspec(dllimport) NTSTATUS __stdcall NtReadFile(
    PVOID FileHandle, PVOID Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatus, PVOID Buffer, ULONG Length,
    PVOID ByteOffset, PVOID Key);
__declspec(dllimport) NTSTATUS __stdcall NtWriteFile(
    PVOID FileHandle, PVOID Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatus, PVOID Buffer, ULONG Length,
    PVOID ByteOffset, PVOID Key);
__declspec(dllimport) NTSTATUS __stdcall NtClose(PVOID Handle);
__declspec(dllimport) NTSTATUS __stdcall NtCreateFile(
    PVOID *FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjAttr,
    PIO_STATUS_BLOCK IoStatus, PVOID AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
    PVOID EaBuffer, ULONG EaLength);
__declspec(dllimport) void __stdcall RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
__declspec(dllimport) void __stdcall NtTerminateProcess(PVOID, NTSTATUS);
__declspec(dllimport) PVOID __stdcall RtlAllocateHeap(PVOID, ULONG, ULONG);
__declspec(dllimport) PVOID __stdcall RtlProcessHeap(void);
__declspec(dllimport) void __stdcall RtlFreeHeap(PVOID, ULONG, PVOID);

#define InitializeObjectAttributes(p, n, a, r, s) \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = (r); \
    (p)->ObjectName = (n); \
    (p)->Attributes = (a); \
    (p)->SecurityDescriptor = (s); \
    (p)->SecurityQualityOfService = 0

/* ---- PE header magic ---- */
#define PE_MZ_SIGNATURE  0x5A4D
#define PE_NT_SIGNATURE  0x00004550

/* ---- Simple log helper ---- */
static PVOID g_LogHandle = (PVOID)-1;

static void WriteLog(PVOID fh, const char *msg, ULONG len)
{
    IO_STATUS_BLOCK iosb = {0};
    NtWriteFile(fh, 0, 0, 0, &iosb, (PVOID)msg, len, 0, 0);
}

/* ---- Check PE header integrity: verify MZ + PE signature ---- */
static int CheckPeHeader(PVOID buf, ULONG size)
{
    if (size < 64) return 0;
    WORD *magic = (WORD *)buf;
    if (*magic != PE_MZ_SIGNATURE) return 0;

    ULONG e_lfanew = *(ULONG *)((UCHAR *)buf + 0x3C);
    if (e_lfanew >= size - 4) return 0;

    ULONG *ntSig = (ULONG *)((UCHAR *)buf + e_lfanew);
    if (*ntSig != PE_NT_SIGNATURE) return 0;

    return 1; /* valid PE */
}

/* ---- Entry point for native application ---- */
void __stdcall NtProcessStartup(PVOID startupInfo)
{
    NTSTATUS                    status;
    IO_STATUS_BLOCK             iosb;
    OBJECT_ATTRIBUTES           oa;
    UNICODE_STRING              dirPath, logPath;
    PVOID                       dirHandle = (PVOID)-1;
    PVOID                       fileHandle = (PVOID)-1;
    UCHAR                       dirBuf[4096];
    UCHAR                       fileBuf[512];
    FILE_DIRECTORY_INFORMATION *entry;
    WCHAR                       filePath[512];
    ULONG                       offset;
    int                         restartScan = 1;
    int                         scannedCount = 0, badCount = 0;

    (void)startupInfo;

    /* Open log file */
    RtlInitUnicodeString(&logPath, L"\\SystemRoot\\Temp\\PsavBootScan.log");
    InitializeObjectAttributes(&oa, &logPath, OBJ_CASE_INSENSITIVE, 0, 0);
    NtCreateFile(&g_LogHandle, FILE_GENERIC_WRITE, &oa, &iosb, 0,
                 0x20 /*FILE_ATTRIBUTE_ARCHIVE*/, 0,
                 FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                 0, 0);

    WriteLog(g_LogHandle, "PsavBoot: scan started\r\n", 24);

    /* Open System32 directory */
    RtlInitUnicodeString(&dirPath, L"\\SystemRoot\\System32");
    InitializeObjectAttributes(&oa, &dirPath, OBJ_CASE_INSENSITIVE, 0, 0);
    status = NtOpenFile(&dirHandle,
                        FILE_LIST_DIRECTORY | SYNCHRONIZE,
                        &oa, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);
    if (!NT_SUCCESS(status)) {
        WriteLog(g_LogHandle, "PsavBoot: cannot open System32\r\n", 32);
        goto Done;
    }

    /* Iterate directory entries */
    while (1) {
        status = NtQueryDirectoryFile(dirHandle, 0, 0, 0, &iosb,
                                      dirBuf, sizeof(dirBuf),
                                      1 /* FileDirectoryInformation */,
                                      0, 0, restartScan);
        restartScan = 0;
        if (!NT_SUCCESS(status) || status == STATUS_NO_MORE_FILES) break;

        offset = 0;
        do {
            entry = (FILE_DIRECTORY_INFORMATION *)(dirBuf + offset);

            /* Process only .exe and .dll files */
            ULONG nameLen = entry->FileNameLength / sizeof(WCHAR);
            if (nameLen > 4) {
                WCHAR *ext = &entry->FileName[nameLen - 4];
                int isDll = (ext[0]=='.' && (ext[1]=='d'||ext[1]=='D') &&
                             (ext[2]=='l'||ext[2]=='L') && (ext[3]=='l'||ext[3]=='L'));
                int isExe = (ext[0]=='.' && (ext[1]=='e'||ext[1]=='E') &&
                             (ext[2]=='x'||ext[2]=='X') && (ext[3]=='e'||ext[3]=='E'));
                if (isDll || isExe) {
                    /* Build full path: \SystemRoot\System32\<name> */
                    if (21 + nameLen + 1 < 512) {
                        int i;
                        const WCHAR prefix[] = L"\\SystemRoot\\System32\\";
                        for (i = 0; i < 21; i++) filePath[i] = prefix[i];
                        for (i = 0; i < (int)nameLen; i++) filePath[21+i] = entry->FileName[i];
                        filePath[21+nameLen] = 0;

                        UNICODE_STRING fpUs;
                        fpUs.Buffer = filePath;
                        fpUs.Length = (USHORT)((21+nameLen) * sizeof(WCHAR));
                        fpUs.MaximumLength = fpUs.Length + sizeof(WCHAR);

                        InitializeObjectAttributes(&oa, &fpUs, OBJ_CASE_INSENSITIVE, 0, 0);
                        status = NtOpenFile(&fileHandle, FILE_GENERIC_READ, &oa, &iosb,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                                           FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
                        if (NT_SUCCESS(status)) {
                            IO_STATUS_BLOCK readIosb = {0};
                            NtReadFile(fileHandle, 0, 0, 0, &readIosb, fileBuf, sizeof(fileBuf), 0, 0);
                            ULONG bytesRead = (ULONG)readIosb.Information;

                            scannedCount++;
                            if (!CheckPeHeader(fileBuf, bytesRead)) {
                                badCount++;
                                /* Log corrupt PE */
                                WriteLog(g_LogHandle, "BAD PE: ", 8);
                                /* Write filename (ASCII approximation) */
                                char nameBuf[256];
                                int k;
                                for (k = 0; k < (int)nameLen && k < 255; k++)
                                    nameBuf[k] = (char)entry->FileName[k];
                                nameBuf[k] = 0;
                                WriteLog(g_LogHandle, nameBuf, nameLen);
                                WriteLog(g_LogHandle, "\r\n", 2);
                            }
                            NtClose(fileHandle);
                            fileHandle = (PVOID)-1;
                        }
                    }
                }
            }

            if (entry->NextEntryOffset == 0) break;
            offset += entry->NextEntryOffset;
        } while (offset < sizeof(dirBuf));
    }

    /* Write summary */
    WriteLog(g_LogHandle, "PsavBoot: scan complete\r\n", 25);

Done:
    if (dirHandle != (PVOID)-1) NtClose(dirHandle);
    if (g_LogHandle != (PVOID)-1) NtClose(g_LogHandle);
    NtTerminateProcess((PVOID)-1, STATUS_SUCCESS);
}
