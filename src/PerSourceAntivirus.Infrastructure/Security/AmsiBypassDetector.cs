using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using ProcessModule = System.Diagnostics.ProcessModule;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class AmsiBypassDetector : IAmsiBypassDetector
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    private static readonly string[] TargetProcessNames =
        ["powershell", "pwsh", "cscript", "wscript", "mshta"];

    private static readonly byte[] ExpectedAmsiScanBufferBytes =
        [0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10];

    private static readonly byte[] ExpectedAmsiOpenSessionBytes =
        [0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20];

    private static readonly byte[][] PatchPatterns =
    [
        [0xC3],
        [0x31, 0xC0],
        [0xB8, 0x57, 0x00, 0x07, 0x80],
        [0x48, 0x31, 0xC0],
        [0x33, 0xC0],
    ];

    private bool _running;
    private CancellationTokenSource? _cts;

    public event EventHandler<AmsiBypassAlertEventArgs>? AlertDetected;

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        while (!_cts.Token.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(60), _cts.Token).ConfigureAwait(false);

            foreach (var alert in ScanAllTargetProcesses())
            {
                AlertDetected?.Invoke(this, new AmsiBypassAlertEventArgs(alert));
            }
        }

        _running = false;
    }

    public void StopMonitoring()
    {
        _cts?.Cancel();
        _running = false;
    }

    private IEnumerable<AmsiBypassAlert> ScanAllTargetProcesses()
    {
        foreach (var name in TargetProcessNames)
        {
            SysProcess[] procs;
            try
            {
                procs = SysProcess.GetProcessesByName(name);
            }
            catch
            {
                continue;
            }

            foreach (var proc in procs)
            {
                using (proc)
                {
                    foreach (var alert in ScanProcess(proc))
                        yield return alert;
                }
            }
        }
    }

    private IEnumerable<AmsiBypassAlert> ScanProcess(SysProcess proc)
    {
        bool amsiLoaded = false;
        System.Diagnostics.ProcessModule? amsiModule = null;

        try
        {
            foreach (System.Diagnostics.ProcessModule module in proc.Modules)
            {
                if (module.ModuleName?.Equals("amsi.dll", StringComparison.OrdinalIgnoreCase) == true)
                {
                    amsiLoaded = true;
                    amsiModule = module;
                    break;
                }
            }
        }
        catch
        {
            yield break;
        }

        if (!amsiLoaded && IsTargetProcess(proc.ProcessName))
        {
            yield return new AmsiBypassAlert
            {
                Id = Guid.NewGuid(),
                ProcessName = proc.ProcessName,
                ProcessId = proc.Id,
                BypassMethod = "UnloadAmsiDll",
                Details = "amsi.dll is not loaded in the target process",
                AffectedFunction = "amsi.dll",
                Severity = 9,
                DetectedAtUtc = DateTime.UtcNow
            };
            yield break;
        }

        if (amsiModule == null)
            yield break;

        var amsiDllPath = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "amsi.dll");

        long scanBufferOffset = 0;
        long openSessionOffset = 0;

        try
        {
            using var fs = System.IO.File.OpenRead(amsiDllPath);
            using var br = new System.IO.BinaryReader(fs);
            scanBufferOffset = FindExportOffset(br, "AmsiScanBuffer");
            openSessionOffset = FindExportOffset(br, "AmsiOpenSession");
        }
        catch
        {
            yield break;
        }

        if (scanBufferOffset > 0)
        {
            var baseAddr = amsiModule.BaseAddress;
            var funcAddr = new IntPtr(baseAddr.ToInt64() + scanBufferOffset);
            var bytes = ReadRemoteBytes(proc, funcAddr, 10);

            if (bytes != null)
            {
                if (IsPatchedBytes(bytes))
                {
                    yield return new AmsiBypassAlert
                    {
                        Id = Guid.NewGuid(),
                        ProcessName = proc.ProcessName,
                        ProcessId = proc.Id,
                        BypassMethod = "PatchAmsiScanBuffer",
                        Details = $"Expected: {FormatBytes(ExpectedAmsiScanBufferBytes)} Found: {FormatBytes(bytes)}",
                        AffectedFunction = "AmsiScanBuffer",
                        Severity = 9,
                        DetectedAtUtc = DateTime.UtcNow
                    };
                }
            }
        }

        if (openSessionOffset > 0)
        {
            var baseAddr = amsiModule.BaseAddress;
            var funcAddr = new IntPtr(baseAddr.ToInt64() + openSessionOffset);
            var bytes = ReadRemoteBytes(proc, funcAddr, 10);

            if (bytes != null && IsPatchedBytes(bytes))
            {
                yield return new AmsiBypassAlert
                {
                    Id = Guid.NewGuid(),
                    ProcessName = proc.ProcessName,
                    ProcessId = proc.Id,
                    BypassMethod = "FakeContext",
                    Details = $"Expected: {FormatBytes(ExpectedAmsiOpenSessionBytes)} Found: {FormatBytes(bytes)}",
                    AffectedFunction = "AmsiOpenSession",
                    Severity = 9,
                    DetectedAtUtc = DateTime.UtcNow
                };
            }
        }
    }

    private static bool IsTargetProcess(string name)
        => TargetProcessNames.Any(t => t.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static bool IsPatchedBytes(byte[] bytes)
    {
        foreach (var pattern in PatchPatterns)
        {
            if (bytes.Length >= pattern.Length)
            {
                bool match = true;
                for (int i = 0; i < pattern.Length; i++)
                {
                    if (bytes[i] != pattern[i]) { match = false; break; }
                }
                if (match) return true;
            }
        }

        int diffCount = 0;
        for (int i = 0; i < Math.Min(bytes.Length, ExpectedAmsiScanBufferBytes.Length); i++)
        {
            if (bytes[i] != ExpectedAmsiScanBufferBytes[i])
                diffCount++;
        }
        return diffCount >= 5;
    }

    private static byte[]? ReadRemoteBytes(SysProcess proc, IntPtr address, int count)
    {
        var hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProcess == IntPtr.Zero)
            return null;

        try
        {
            var buffer = new byte[count];
            if (ReadProcessMemory(hProcess, address, buffer, count, out int read) && read == count)
                return buffer;
            return null;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    private static long FindExportOffset(System.IO.BinaryReader br, string exportName)
    {
        br.BaseStream.Seek(0, System.IO.SeekOrigin.Begin);

        if (br.ReadUInt16() != 0x5A4D)
            return 0;

        br.BaseStream.Seek(0x3C, System.IO.SeekOrigin.Begin);
        var peOffset = br.ReadInt32();

        br.BaseStream.Seek(peOffset, System.IO.SeekOrigin.Begin);
        if (br.ReadUInt32() != 0x00004550)
            return 0;

        var machine = br.ReadUInt16();
        br.ReadUInt16();
        br.ReadUInt32();
        br.ReadUInt32();
        br.ReadUInt32();
        br.ReadUInt16();
        var characteristics = br.ReadUInt16();

        var magic = br.ReadUInt16();
        bool isPe32Plus = magic == 0x20B;

        br.BaseStream.Seek(isPe32Plus ? peOffset + 24 + 16 : peOffset + 24 + 12, System.IO.SeekOrigin.Begin);

        uint exportVa;
        if (isPe32Plus)
        {
            br.BaseStream.Seek(peOffset + 24 + 112, System.IO.SeekOrigin.Begin);
        }
        else
        {
            br.BaseStream.Seek(peOffset + 24 + 96, System.IO.SeekOrigin.Begin);
        }
        exportVa = br.ReadUInt32();
        br.ReadUInt32();

        if (exportVa == 0)
            return 0;

        var sectionOffset = RvaToOffset(br, peOffset, exportVa);
        if (sectionOffset == 0)
            return 0;

        br.BaseStream.Seek(sectionOffset + 12, System.IO.SeekOrigin.Begin);
        var nameRva = br.ReadUInt32();
        var ordinalBase = br.ReadUInt32();
        var numberOfFunctions = br.ReadUInt32();
        var numberOfNames = br.ReadUInt32();
        var addressTableRva = br.ReadUInt32();
        var namePointersRva = br.ReadUInt32();
        var ordinalsRva = br.ReadUInt32();

        var namePointersOffset = RvaToOffset(br, peOffset, namePointersRva);
        var ordinalsOffset = RvaToOffset(br, peOffset, ordinalsRva);
        var addressTableOffset = RvaToOffset(br, peOffset, addressTableRva);

        if (namePointersOffset == 0 || ordinalsOffset == 0 || addressTableOffset == 0)
            return 0;

        for (uint i = 0; i < numberOfNames; i++)
        {
            br.BaseStream.Seek(namePointersOffset + i * 4, System.IO.SeekOrigin.Begin);
            var nameRvaEntry = br.ReadUInt32();
            var nameOffset = RvaToOffset(br, peOffset, nameRvaEntry);
            if (nameOffset == 0)
                continue;

            br.BaseStream.Seek(nameOffset, System.IO.SeekOrigin.Begin);
            var nameBytes = new System.Collections.Generic.List<byte>();
            byte b;
            while ((b = br.ReadByte()) != 0)
                nameBytes.Add(b);
            var name = System.Text.Encoding.ASCII.GetString(nameBytes.ToArray());

            if (name == exportName)
            {
                br.BaseStream.Seek(ordinalsOffset + i * 2, System.IO.SeekOrigin.Begin);
                var ordinalIndex = br.ReadUInt16();

                br.BaseStream.Seek(addressTableOffset + ordinalIndex * 4, System.IO.SeekOrigin.Begin);
                var funcRva = br.ReadUInt32();
                return funcRva;
            }
        }

        return 0;
    }

    private static long RvaToOffset(System.IO.BinaryReader br, int peOffset, uint rva)
    {
        var savedPos = br.BaseStream.Position;
        try
        {
            br.BaseStream.Seek(peOffset + 6, System.IO.SeekOrigin.Begin);
            var numberOfSections = br.ReadUInt16();
            br.BaseStream.Seek(peOffset + 20, System.IO.SeekOrigin.Begin);
            var sizeOfOptionalHeader = br.ReadUInt16();
            var sectionTableStart = peOffset + 24 + sizeOfOptionalHeader;

            for (int i = 0; i < numberOfSections; i++)
            {
                br.BaseStream.Seek(sectionTableStart + i * 40, System.IO.SeekOrigin.Begin);
                br.ReadUInt64();
                var virtualSize = br.ReadUInt32();
                var virtualAddress = br.ReadUInt32();
                var sizeOfRawData = br.ReadUInt32();
                var pointerToRawData = br.ReadUInt32();

                if (rva >= virtualAddress && rva < virtualAddress + Math.Max(virtualSize, sizeOfRawData))
                {
                    return pointerToRawData + (rva - virtualAddress);
                }
            }
        }
        finally
        {
            br.BaseStream.Position = savedPos;
        }
        return 0;
    }

    private static string FormatBytes(byte[] bytes)
        => string.Join(" ", bytes.Select(b => $"{b:X2}"));
}
