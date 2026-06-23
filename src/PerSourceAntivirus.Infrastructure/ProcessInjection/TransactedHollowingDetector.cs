using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<ITransactedHollowingDetector, TransactedHollowingDetector>();
[SupportedOSPlatform("windows")]
public sealed class TransactedHollowingDetector : ITransactedHollowingDetector
{
    private readonly ITransactedHollowingAlertRepository _repository;
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private volatile bool _running;

    private const int PROCESS_VM_READ = 0x0010;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_IMAGE = 0x1000000;
    // Executable page protection mask
    private const uint PAGE_EXECUTE_MASK = 0xF0;

    private static readonly string TempPath =
        System.IO.Path.GetTempPath().TrimEnd(System.IO.Path.DirectorySeparatorChar,
            System.IO.Path.AltDirectorySeparatorChar);

    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            .TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar);

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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(IntPtr hProcess, IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetMappedFileName(IntPtr hProcess, IntPtr lpv, StringBuilder lpFilename, uint nSize);

    public event EventHandler<TransactedHollowingAlertEventArgs>? AlertDetected;

    public TransactedHollowingDetector(ITransactedHollowingAlertRepository repository)
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
            // Phase 1: Check module list for missing files or suspicious paths
            var moduleHandles = new IntPtr[1024];
            if (EnumProcessModules(handle, moduleHandles, (uint)(moduleHandles.Length * IntPtr.Size), out uint needed))
            {
                int moduleCount = (int)(needed / (uint)IntPtr.Size);
                var sb = new StringBuilder(1024);

                for (int m = 0; m < moduleCount; m++)
                {
                    if (ct.IsCancellationRequested) break;
                    if (moduleHandles[m] == IntPtr.Zero) continue;

                    sb.Clear();
                    if (GetModuleFileNameEx(handle, moduleHandles[m], sb, (uint)sb.Capacity) == 0)
                        continue;

                    string modulePath = sb.ToString();
                    if (string.IsNullOrEmpty(modulePath)) continue;

                    // Check 1: module file not on disk
                    if (!System.IO.File.Exists(modulePath))
                    {
                        await FireAlertIfNewAsync(pid, procName, modulePath, false,
                            "ModuleFileNotOnDisk", 9, ct);
                    }
                    // Check 2: module loaded from temp/localappdata
                    else if (IsInTempDirectory(modulePath))
                    {
                        await FireAlertIfNewAsync(pid, procName, modulePath, true,
                            "TransactedPath", 7, ct);
                    }
                }
            }

            // Phase 2: Walk VirtualQueryEx for MEM_IMAGE regions
            var address = IntPtr.Zero;
            var mappedSb = new StringBuilder(1024);

            while (VirtualQueryEx(handle, address, out var mbi,
                (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
            {
                var regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
                {
                    mappedSb.Clear();
                    uint nameLen = GetMappedFileName(handle, mbi.BaseAddress, mappedSb, (uint)mappedSb.Capacity);

                    if (nameLen == 0)
                    {
                        // MEM_IMAGE region with no mapped file backing
                        string regionKey = $"{pid}_0x{mbi.BaseAddress.ToInt64():X}";
                        bool hasExecuteProtect = (mbi.Protect & PAGE_EXECUTE_MASK) != 0;

                        if (hasExecuteProtect)
                        {
                            // ImageMappedPrivate: image section mapped with no file — hallmark of transacted hollowing
                            await FireAlertIfNewAsync(pid, procName,
                                $"<unmapped:0x{mbi.BaseAddress.ToInt64():X}>",
                                false, "ImageMappedPrivate", 9, ct);
                        }
                        else
                        {
                            await FireAlertIfNewAsync(pid, procName,
                                $"<unmapped:0x{mbi.BaseAddress.ToInt64():X}>",
                                false, "MappedSectionNoFile", 8, ct);
                        }
                    }
                }

                try
                {
                    address = new IntPtr(mbi.BaseAddress.ToInt64() + regionSize);
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

    private async Task FireAlertIfNewAsync(int pid, string procName, string modulePath,
        bool fileExists, string detectionMethod, int severity, CancellationToken ct)
    {
        var key = $"{pid}_{modulePath}";
        var now = DateTime.UtcNow;

        if (_recentAlerts.TryGetValue(key, out var last) && (now - last).TotalMinutes < 10)
            return;

        _recentAlerts[key] = now;

        var alert = new TransactedHollowingAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = procName,
            ProcessId = pid,
            SuspiciousModulePath = modulePath,
            ModuleFileExistsOnDisk = fileExists,
            DetectionMethod = detectionMethod,
            Severity = severity,
            DetectedAtUtc = now
        };

        try { await _repository.AddAsync(alert, ct); }
        catch (Exception) { }

        AlertDetected?.Invoke(this, new TransactedHollowingAlertEventArgs(alert));
    }

    private static bool IsInTempDirectory(string path)
    {
        return path.StartsWith(TempPath, StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(LocalAppData, StringComparison.OrdinalIgnoreCase);
    }
}
