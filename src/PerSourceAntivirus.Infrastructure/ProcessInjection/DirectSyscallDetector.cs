using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

[SupportedOSPlatform("windows")]
public sealed class DirectSyscallDetector : IDirectSyscallDetector
{
    private readonly IDirectSyscallAlertRepository _repository;
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private volatile bool _running;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

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
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    // syscall: 0F 05, sysenter: 0F 34
    private static readonly byte[] PatternSyscall = [0x0F, 0x05];
    private static readonly byte[] PatternSysenter = [0x0F, 0x34];

    public event EventHandler<DirectSyscallAlertEventArgs>? AlertDetected;

    public DirectSyscallDetector(IDirectSyscallAlertRepository repository)
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
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
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

        int currentPid;
        try { currentPid = SysProcess.GetCurrentProcess().Id; }
        catch (Exception) { currentPid = -1; }

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            try { await ScanProcessAsync(proc, currentPid, ct); }
            catch (Exception) { }
            finally { proc.Dispose(); }
        }
    }

    private async Task ScanProcessAsync(SysProcess proc, int currentPid, CancellationToken ct)
    {
        int pid;
        string procName;
        try
        {
            pid = proc.Id;
            procName = proc.ProcessName;
        }
        catch (Exception) { return; }

        if (pid <= 4 || pid == currentPid) return;

        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return;

        try
        {
            var modules = GetModuleList(handle);
            var address = IntPtr.Zero;

            while (VirtualQueryEx(handle, address, out var mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
            {
                var regionSize = (long)mbi.RegionSize;
                if (regionSize <= 0) break;

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && IsExecutable(mbi.Protect))
                {
                    var readSize = (int)Math.Min(regionSize, 65536);
                    var buffer = new byte[readSize];
                    if (ReadProcessMemory(handle, mbi.BaseAddress, buffer, readSize, out int bytesRead) && bytesRead > 0)
                    {
                        await ScanBufferForSyscallsAsync(handle, pid, procName, mbi.BaseAddress, buffer, bytesRead, modules, ct);
                    }
                }

                try { address = new IntPtr(address.ToInt64() + regionSize); }
                catch (OverflowException) { break; }

                if (address.ToInt64() < 0 || address.ToInt64() >= 0x7FFFFFFF0000L) break;
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private async Task ScanBufferForSyscallsAsync(IntPtr handle, int pid, string procName,
        IntPtr regionBase, byte[] data, int dataLen,
        List<(long baseAddr, long size, string path)> modules, CancellationToken ct)
    {
        for (int i = 0; i <= dataLen - 2; i++)
        {
            string? instrType = null;
            if (data[i] == 0x0F && data[i + 1] == 0x05)
                instrType = "SYSCALL";
            else if (data[i] == 0x0F && data[i + 1] == 0x34)
                instrType = "SYSENTER";

            if (instrType == null) continue;

            ulong instrAddr = (ulong)regionBase.ToInt64() + (ulong)i;
            var (modulePath, isSystem) = FindContainingModule((long)instrAddr, modules);

            // Skip if in ntdll or win32u (expected locations for syscalls)
            if (isSystem && (modulePath.Contains("ntdll", StringComparison.OrdinalIgnoreCase) ||
                             modulePath.Contains("win32u", StringComparison.OrdinalIgnoreCase)))
                continue;

            await FireAlertIfNewAsync(pid, procName, instrAddr, instrType, modulePath, isSystem, ct);
        }
    }

    private async Task FireAlertIfNewAsync(int pid, string procName, ulong addr,
        string instrType, string modulePath, bool isSystem, CancellationToken ct)
    {
        var key = $"{pid}_{addr}";
        var now = DateTime.UtcNow;

        if (_recentAlerts.TryGetValue(key, out var last) && (now - last).TotalMinutes < 10)
            return;

        _recentAlerts[key] = now;

        int severity = isSystem ? 7 : 9;

        var alert = new DirectSyscallAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = procName,
            ProcessId = pid,
            SyscallInstructionAddress = addr,
            InstructionType = instrType,
            ContainingModulePath = modulePath,
            IsInSystemModule = isSystem,
            Severity = severity,
            DetectedAtUtc = now
        };

        try { await _repository.AddAsync(alert, ct); }
        catch (Exception) { }

        AlertDetected?.Invoke(this, new DirectSyscallAlertEventArgs(alert));
    }

    private static (string path, bool isSystem) FindContainingModule(long addr, List<(long baseAddr, long size, string path)> modules)
    {
        foreach (var (baseAddr, size, path) in modules)
        {
            if (addr >= baseAddr && addr < baseAddr + size)
            {
                bool isSystem = path.Contains("System32", StringComparison.OrdinalIgnoreCase) ||
                                path.Contains("SysWOW64", StringComparison.OrdinalIgnoreCase);
                return (path, isSystem);
            }
        }
        return ("Unknown", false);
    }

    private static List<(long baseAddr, long size, string path)> GetModuleList(IntPtr handle)
    {
        var result = new List<(long, long, string)>();
        try
        {
            var mods = new IntPtr[1024];
            if (!EnumProcessModules(handle, mods, (uint)(mods.Length * IntPtr.Size), out uint needed))
                return result;

            int count = (int)(needed / (uint)IntPtr.Size);
            var sb = new StringBuilder(1024);

            for (int i = 0; i < count; i++)
            {
                if (mods[i] == IntPtr.Zero) continue;
                sb.Clear();
                if (GetModuleFileNameEx(handle, mods[i], sb, (uint)sb.Capacity) == 0) continue;
                var path = sb.ToString();

                // Use VirtualQueryEx to determine size
                if (VirtualQueryEx(handle, mods[i], out var mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
                {
                    long size = Math.Max((long)mbi.RegionSize, 4 * 1024 * 1024);
                    result.Add((mods[i].ToInt64(), size, path));
                }
                else
                {
                    result.Add((mods[i].ToInt64(), 4 * 1024 * 1024, path));
                }
            }
        }
        catch (Exception) { }
        return result;
    }

    private static bool IsExecutable(uint protect)
    {
        return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }
}
