using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

[SupportedOSPlatform("windows")]
public sealed class HeapSprayDetector : IHeapSprayDetector
{
    private readonly IHeapSprayAlertRepository _repository;
    private readonly ConcurrentDictionary<int, DateTime> _alertedPids = new();
    private volatile bool _running;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

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
    private const long ONE_MB = 1_048_576;
    private const long HUNDRED_MB = 104_857_600;

    public event EventHandler<HeapSprayAlertEventArgs>? AlertDetected;

    public HeapSprayDetector(IHeapSprayAlertRepository repository)
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
                await Task.Delay(TimeSpan.FromSeconds(15), ct);
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

        var now = DateTime.UtcNow;
        if (_alertedPids.TryGetValue(pid, out var last) && (now - last).TotalMinutes < 5)
            return;

        // Skip obvious system processes
        if (IsSystemProcess(procName)) return;

        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return;

        try
        {
            var regions = CollectLargePrivateRegions(handle);
            if (regions.Count == 0) return;

            long totalBytes = regions.Sum(r => r.size);
            if (totalBytes < HUNDRED_MB)
            {
                // Check uniform-size heuristic regardless of total size
                CheckUniformSizeAndAlert(pid, procName, regions, totalBytes, now, ct);
                return;
            }

            // Calculate average entropy from sampled bytes
            double avgEntropy = await CalculateAverageEntropyAsync(handle, regions);

            bool fired = false;

            if (avgEntropy < 3.0)
            {
                string reason = avgEntropy < 1.5 ? "ExtremeLowEntropyLargeAlloc" : "LowEntropyHeapSpray";
                int severity = avgEntropy < 1.5 ? 9 : 7;

                _alertedPids[pid] = now;
                fired = true;

                var alert = new HeapSprayAlert
                {
                    Id = Guid.NewGuid(),
                    ProcessName = procName,
                    ProcessId = pid,
                    TotalPrivateCommittedBytes = totalBytes,
                    SuspiciousRegionCount = regions.Count,
                    AverageRegionEntropy = avgEntropy,
                    SuspicionReason = reason,
                    Severity = severity,
                    DetectedAtUtc = now
                };

                try { await _repository.AddAsync(alert, ct); }
                catch (Exception) { }
                AlertDetected?.Invoke(this, new HeapSprayAlertEventArgs(alert));
            }

            if (!fired)
            {
                CheckUniformSizeAndAlert(pid, procName, regions, totalBytes, now, ct);
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private void CheckUniformSizeAndAlert(int pid, string procName,
        List<(IntPtr baseAddr, long size)> regions, long totalBytes, DateTime now, CancellationToken ct)
    {
        // Group by size bucket (size / 4096) — bucket granularity of 4KB
        var buckets = new Dictionary<long, int>();
        foreach (var (_, size) in regions)
        {
            long bucket = size / 4096;
            buckets.TryGetValue(bucket, out int count);
            buckets[bucket] = count + 1;
        }

        if (buckets.Values.Any(v => v > 50))
        {
            _alertedPids[pid] = now;

            var alert = new HeapSprayAlert
            {
                Id = Guid.NewGuid(),
                ProcessName = procName,
                ProcessId = pid,
                TotalPrivateCommittedBytes = totalBytes,
                SuspiciousRegionCount = regions.Count,
                AverageRegionEntropy = 0,
                SuspicionReason = "UniformSizeAlloc",
                Severity = 8,
                DetectedAtUtc = now
            };

            try { _repository.AddAsync(alert, ct).GetAwaiter().GetResult(); }
            catch (Exception) { }
            AlertDetected?.Invoke(this, new HeapSprayAlertEventArgs(alert));
        }
    }

    private static List<(IntPtr baseAddr, long size)> CollectLargePrivateRegions(IntPtr handle)
    {
        var result = new List<(IntPtr, long)>();
        var address = IntPtr.Zero;

        while (VirtualQueryEx(handle, address, out var mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
        {
            long regionSize = (long)mbi.RegionSize;
            if (regionSize <= 0) break;

            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && regionSize >= ONE_MB)
            {
                result.Add((mbi.BaseAddress, regionSize));
            }

            try { address = new IntPtr(address.ToInt64() + regionSize); }
            catch (OverflowException) { break; }

            if (address.ToInt64() < 0 || address.ToInt64() >= 0x7FFFFFFF0000L) break;
        }

        return result;
    }

    private static async Task<double> CalculateAverageEntropyAsync(IntPtr handle, List<(IntPtr baseAddr, long size)> regions)
    {
        double total = 0;
        int sampled = 0;
        var buffer = new byte[4096];

        foreach (var (baseAddr, _) in regions)
        {
            if (ReadProcessMemory(handle, baseAddr, buffer, buffer.Length, out int bytesRead) && bytesRead > 0)
            {
                total += CalculateEntropy(buffer, bytesRead);
                sampled++;
            }
            // Yield occasionally to avoid blocking
            if (sampled % 10 == 0)
                await Task.Yield();
        }

        return sampled > 0 ? total / sampled : 0;
    }

    private static double CalculateEntropy(byte[] data, int length)
    {
        if (length == 0) return 0;
        var freq = new int[256];
        for (int i = 0; i < length; i++) freq[data[i]]++;
        double entropy = 0;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            double p = (double)f / length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static bool IsSystemProcess(string procName)
    {
        return procName.Equals("System", StringComparison.OrdinalIgnoreCase) ||
               procName.Equals("smss", StringComparison.OrdinalIgnoreCase) ||
               procName.Equals("csrss", StringComparison.OrdinalIgnoreCase) ||
               procName.Equals("wininit", StringComparison.OrdinalIgnoreCase) ||
               procName.Equals("services", StringComparison.OrdinalIgnoreCase) ||
               procName.Equals("lsass", StringComparison.OrdinalIgnoreCase) ||
               procName.Equals("svchost", StringComparison.OrdinalIgnoreCase);
    }
}
