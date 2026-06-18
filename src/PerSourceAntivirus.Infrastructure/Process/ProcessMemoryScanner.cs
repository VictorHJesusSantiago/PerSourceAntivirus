using System.Runtime.InteropServices;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Process;

public class ProcessMemoryScanner(IYaraScanner yaraScanner) : IProcessMemoryScanner
{
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint MemCommit = 0x1000;
    private const uint MemPrivate = 0x20000;
    private const uint MemMapped = 0x40000;
    private const uint MemImage = 0x1000000;
    private const uint PageExecuteReadwrite = 0x40;
    private const int MaxRegionBytes = 50 * 1024 * 1024;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(nint hProcess, nint lpAddress,
        out MemoryBasicInformation lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(nint hProcess, nint lpBaseAddress,
        byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public nint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public Task<ProcessMemoryScanResult> ScanProcessAsync(int processId, CancellationToken ct = default)
    {
        string processName;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(processId);
            processName = p.ProcessName;
        }
        catch { processName = "unknown"; }

        var hProcess = OpenProcess(ProcessVmRead | ProcessQueryInformation, false, processId);
        if (hProcess == nint.Zero)
        {
            var err = Marshal.GetLastWin32Error();
            return Task.FromResult(new ProcessMemoryScanResult(processId, processName, 0, [],
                false, $"OpenProcess failed: Win32 error {err}"));
        }

        try
        {
            var matches = new List<ProcessMemoryMatch>();
            var regionsScanned = 0;
            var address = nint.Zero;

            while (!ct.IsCancellationRequested)
            {
                if (!VirtualQueryEx(hProcess, address, out var mbi,
                    (uint)Marshal.SizeOf<MemoryBasicInformation>()))
                    break;

                var regionSize = mbi.RegionSize.ToInt64();
                var nextAddress = new nint(mbi.BaseAddress.ToInt64() + regionSize);

                var shouldScan = mbi.State == MemCommit
                    && regionSize is > 0 and <= MaxRegionBytes
                    && (mbi.Type == MemPrivate
                        || mbi.Type == MemMapped
                        || (mbi.Type == MemImage && mbi.Protect == PageExecuteReadwrite));

                if (shouldScan)
                {
                    var buffer = new byte[regionSize];
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, buffer.Length, out var bytesRead)
                        && bytesRead > 0)
                    {
                        var data = bytesRead < buffer.Length ? buffer[..bytesRead] : buffer;
                        var yaraMatches = yaraScanner.ScanMemory(data);
                        foreach (var m in yaraMatches)
                            matches.Add(new ProcessMemoryMatch(
                                mbi.BaseAddress.ToInt64(), regionSize,
                                m.RuleIdentifier, m.Tags));
                        regionsScanned++;
                    }
                }

                if (nextAddress.ToInt64() <= address.ToInt64())
                    break;
                address = nextAddress;
            }

            return Task.FromResult(new ProcessMemoryScanResult(
                processId, processName, regionsScanned, matches, true));
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }
}
