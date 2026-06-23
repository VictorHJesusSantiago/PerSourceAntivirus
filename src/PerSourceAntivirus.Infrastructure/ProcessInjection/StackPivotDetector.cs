using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IStackPivotDetector, StackPivotDetector>();
[SupportedOSPlatform("windows")]
public sealed class StackPivotDetector : IStackPivotDetector
{
    private readonly IStackPivotAlertRepository _repository;
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private volatile bool _running;

    private const int PROCESS_VM_READ = 0x0010;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const int THREAD_QUERY_INFORMATION = 0x0040;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;

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

    [StructLayout(LayoutKind.Sequential)]
    private struct THREAD_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr TebBaseAddress;
        public IntPtr UniqueProcessId;
        public IntPtr UniqueThreadId;
        public IntPtr AffinityMask;
        public int Priority;
        public int BasePriority;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, int dwThreadId);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass, ref THREAD_BASIC_INFORMATION threadInformation, int threadInformationLength, out int returnLength);

    public event EventHandler<StackPivotAlertEventArgs>? AlertDetected;

    public StackPivotDetector(IStackPivotAlertRepository repository)
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

        var processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (processHandle == IntPtr.Zero) return;

        try
        {
            // Collect stack ranges from all threads via TEB
            var threadStackRanges = new List<(ulong stackLimit, ulong stackBase)>();

            System.Diagnostics.ProcessThreadCollection threads;
            try { threads = proc.Threads; }
            catch (Exception)
            {
                CloseHandle(processHandle);
                return;
            }

            foreach (System.Diagnostics.ProcessThread thread in threads)
            {
                var threadHandle = OpenThread(THREAD_QUERY_INFORMATION, false, thread.Id);
                if (threadHandle == IntPtr.Zero) continue;

                try
                {
                    var tbi = new THREAD_BASIC_INFORMATION();
                    int returnLength;
                    int status = NtQueryInformationThread(threadHandle, 0, ref tbi,
                        Marshal.SizeOf<THREAD_BASIC_INFORMATION>(), out returnLength);

                    if (status == 0 && tbi.TebBaseAddress != IntPtr.Zero)
                    {
                        // Read StackLimit at TEB+0x08
                        var stackLimitBytes = new byte[8];
                        // Read StackBase at TEB+0x10
                        var stackBaseBytes = new byte[8];

                        bool gotLimit = ReadProcessMemory(processHandle,
                            IntPtr.Add(tbi.TebBaseAddress, 8),
                            stackLimitBytes, 8, out _);

                        bool gotBase = ReadProcessMemory(processHandle,
                            IntPtr.Add(tbi.TebBaseAddress, 16),
                            stackBaseBytes, 8, out _);

                        if (gotLimit && gotBase)
                        {
                            ulong stackLimit = BitConverter.ToUInt64(stackLimitBytes);
                            ulong stackBase = BitConverter.ToUInt64(stackBaseBytes);
                            if (stackBase > stackLimit && stackBase != 0 && stackLimit != 0)
                            {
                                threadStackRanges.Add((stackLimit, stackBase));
                            }
                        }
                    }
                }
                catch (Exception) { }
                finally { CloseHandle(threadHandle); }
            }

            // Walk virtual memory looking for RWX private committed regions
            var address = IntPtr.Zero;
            while (VirtualQueryEx(processHandle, address, out var mbi,
                (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
            {
                var regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                    IsExecutableAndWritable(mbi.Protect))
                {
                    ulong regionBase = (ulong)mbi.BaseAddress.ToInt64();
                    ulong regionEnd = regionBase + (ulong)regionSize;

                    // Check if this RWX region falls outside all known thread stack ranges
                    bool insideAnyStack = false;
                    foreach (var (stackLimit, stackBase) in threadStackRanges)
                    {
                        if (regionBase >= stackLimit && regionEnd <= stackBase)
                        {
                            insideAnyStack = true;
                            break;
                        }
                    }

                    if (!insideAnyStack)
                    {
                        var key = $"{pid}_{regionBase}";
                        var now = DateTime.UtcNow;

                        if (!_recentAlerts.TryGetValue(key, out var last) ||
                            (now - last).TotalMinutes >= 5)
                        {
                            _recentAlerts[key] = now;

                            var alert = new StackPivotAlert
                            {
                                Id = Guid.NewGuid(),
                                ProcessName = procName,
                                ProcessId = pid,
                                ThreadId = 0,
                                RspValue = regionBase,
                                StackBase = threadStackRanges.Count > 0 ? threadStackRanges[0].stackBase : 0,
                                StackLimit = threadStackRanges.Count > 0 ? threadStackRanges[0].stackLimit : 0,
                                SuspicionReason = "RspInHeapRegion",
                                Severity = 8,
                                DetectedAtUtc = now
                            };

                            try { await _repository.AddAsync(alert, ct); }
                            catch (Exception) { }

                            AlertDetected?.Invoke(this, new StackPivotAlertEventArgs(alert));
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
            CloseHandle(processHandle);
        }
    }

    private static bool IsExecutableAndWritable(uint protect)
    {
        return (protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }
}
