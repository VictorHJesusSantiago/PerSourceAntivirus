using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

[SupportedOSPlatform("windows")]
public sealed class HeavensGateDetector : IHeavensGateDetector
{
    private readonly IHeavensGateAlertRepository _repository;
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private volatile bool _running;

    // Known Heaven's Gate byte patterns
    private static readonly byte[] PatternPushRetf = [0x6A, 0x33, 0xCB];           // push 33h; retf
    private static readonly byte[] PatternFarJmpFF2D = [0xFF, 0x2D];               // jmp far [mem]
    private static readonly byte[] PatternFarJmpEA = [0xEA];                       // jmp far imm16:imm32

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(IntPtr hProcess, IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const int PROCESS_VM_READ = 0x0010;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_COMMIT = 0x1000;
    // Executable page protection masks
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    public event EventHandler<HeavensGateAlertEventArgs>? AlertDetected;

    public HeavensGateDetector(IHeavensGateAlertRepository repository)
    {
        _repository = repository;
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        try
        {
            while (!ct.IsCancellationRequested && _running)
            {
                try { await ScanOnceAsync(ct); }
                catch (Exception) { }
                await Task.Delay(TimeSpan.FromSeconds(20), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private async Task ScanOnceAsync(CancellationToken ct)
    {
        SysProcess[] processes;
        try { processes = SysProcess.GetProcesses(); }
        catch (Exception) { return; }

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            try { await ScanProcessAsync(proc, ct); }
            catch (Exception) { }
            finally { proc.Dispose(); }
        }
    }

    private async Task ScanProcessAsync(SysProcess proc, CancellationToken ct)
    {
        int pid;
        string procName;
        try
        {
            pid = proc.Id;
            procName = proc.ProcessName;
        }
        catch (Exception) { return; }

        if (pid <= 4) return;

        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return;

        try
        {
            if (!IsWow64Process(handle, out bool isWow64) || !isWow64)
                return;

            // Build set of system module address ranges to skip
            var systemModuleRanges = BuildSystemModuleRanges(handle);

            var address = IntPtr.Zero;
            while (VirtualQueryEx(handle, address, out var mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
            {
                var regionSize = (long)mbi.RegionSize;
                if (regionSize <= 0) break;

                if (mbi.State == MEM_COMMIT && IsExecutable(mbi.Protect))
                {
                    // Skip if this region belongs to a known system module
                    if (!IsInSystemModuleRange(mbi.BaseAddress, systemModuleRanges))
                    {
                        await ScanRegionAsync(handle, pid, procName, mbi, isWow64, ct);
                    }
                }

                try
                {
                    address = new IntPtr(address.ToInt64() + regionSize);
                }
                catch (OverflowException) { break; }

                if (address.ToInt64() < 0 || address.ToInt64() >= 0x7FFFFFFF0000L) break;
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private async Task ScanRegionAsync(IntPtr handle, int pid, string procName,
        MEMORY_BASIC_INFORMATION mbi, bool isWow64, CancellationToken ct)
    {
        var regionSize = (long)mbi.RegionSize;
        var readSize = (int)Math.Min(regionSize, 65536);
        var buffer = new byte[readSize];

        if (!ReadProcessMemory(handle, mbi.BaseAddress, buffer, readSize, out int bytesRead) || bytesRead == 0)
            return;

        // Pattern a: push 33h; retf — classic Heaven's Gate
        for (int i = 0; i <= bytesRead - PatternPushRetf.Length; i++)
        {
            if (buffer[i] == PatternPushRetf[0] && buffer[i + 1] == PatternPushRetf[1] && buffer[i + 2] == PatternPushRetf[2])
            {
                ulong addr = (ulong)mbi.BaseAddress.ToInt64() + (ulong)i;
                await FireAlertIfNewAsync(pid, procName, addr, "PushRetfCS33",
                    BitConverter.ToString(PatternPushRetf).Replace("-", ""), isWow64, ct);
            }
        }

        // Pattern b: FF 2D (jmp far [mem]) — "FarJmpCS33"
        for (int i = 0; i <= bytesRead - 2; i++)
        {
            if (buffer[i] == 0xFF && buffer[i + 1] == 0x2D)
            {
                ulong addr = (ulong)mbi.BaseAddress.ToInt64() + (ulong)i;
                var matchBytes = new byte[Math.Min(6, bytesRead - i)];
                for (int k = 0; k < matchBytes.Length; k++) matchBytes[k] = buffer[i + k];
                await FireAlertIfNewAsync(pid, procName, addr, "FarJmpCS33",
                    BitConverter.ToString(matchBytes).Replace("-", ""), isWow64, ct);
            }
        }

        // Pattern c: EA <4 bytes> 33 00 — far jmp with CS=0x33 selector
        for (int i = 0; i <= bytesRead - 7; i++)
        {
            if (buffer[i] == 0xEA && buffer[i + 5] == 0x33 && buffer[i + 6] == 0x00)
            {
                ulong addr = (ulong)mbi.BaseAddress.ToInt64() + (ulong)i;
                var matchBytes = new byte[7];
                for (int k = 0; k < 7; k++) matchBytes[k] = buffer[i + k];
                await FireAlertIfNewAsync(pid, procName, addr, "FarJmpCS33Imm",
                    BitConverter.ToString(matchBytes).Replace("-", ""), isWow64, ct);
            }
        }
    }

    private async Task FireAlertIfNewAsync(int pid, string procName, ulong addr,
        string patternType, string patternBytes, bool isWow64, CancellationToken ct)
    {
        var key = $"{pid}_{addr}";
        var now = DateTime.UtcNow;

        if (_recentAlerts.TryGetValue(key, out var last) && (now - last).TotalMinutes < 10)
            return;

        _recentAlerts[key] = now;

        var alert = new HeavensGateAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = procName,
            ProcessId = pid,
            DetectedPatternAddress = addr,
            PatternType = patternType,
            PatternBytes = patternBytes,
            IsWow64Process = isWow64,
            Severity = 8,
            DetectedAtUtc = now
        };

        try { await _repository.AddAsync(alert, ct); }
        catch (Exception) { }

        AlertDetected?.Invoke(this, new HeavensGateAlertEventArgs(alert));
    }

    private static bool IsExecutable(uint protect)
    {
        return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }

    private static List<(long start, long end)> BuildSystemModuleRanges(IntPtr handle)
    {
        var ranges = new List<(long start, long end)>();
        try
        {
            var mods = new IntPtr[1024];
            if (!EnumProcessModules(handle, mods, (uint)(mods.Length * IntPtr.Size), out uint needed))
                return ranges;

            int count = (int)(needed / (uint)IntPtr.Size);
            var sb = new StringBuilder(1024);

            for (int i = 0; i < count; i++)
            {
                if (mods[i] == IntPtr.Zero) continue;
                sb.Clear();
                if (GetModuleFileNameEx(handle, mods[i], sb, (uint)sb.Capacity) == 0) continue;
                var path = sb.ToString();

                if (path.Contains("ntdll", StringComparison.OrdinalIgnoreCase) ||
                    path.Contains("wow64", StringComparison.OrdinalIgnoreCase))
                {
                    // Use VirtualQueryEx to find the size of this module
                    if (VirtualQueryEx(handle, mods[i], out var mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
                    {
                        long start = mods[i].ToInt64();
                        long size = (long)mbi.RegionSize;
                        // Approximate: use at least 4MB for ntdll
                        if (size < 4 * 1024 * 1024) size = 4 * 1024 * 1024;
                        ranges.Add((start, start + size));
                    }
                }
            }
        }
        catch (Exception) { }
        return ranges;
    }

    private static bool IsInSystemModuleRange(IntPtr addr, List<(long start, long end)> ranges)
    {
        long a = addr.ToInt64();
        foreach (var (start, end) in ranges)
        {
            if (a >= start && a < end) return true;
        }
        return false;
    }
}
