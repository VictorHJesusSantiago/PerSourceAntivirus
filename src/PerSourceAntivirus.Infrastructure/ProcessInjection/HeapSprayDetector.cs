using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

[SupportedOSPlatform("windows")]
public sealed class HeapSprayDetector : IHeapSprayDetector
{
    private readonly IServiceScopeFactory _scopeFactory;
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

    public HeapSprayDetector(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    private async Task PersistAsync(HeapSprayAlert alert, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IHeapSprayAlertRepository>();
            await repository.AddAsync(alert, ct).ConfigureAwait(false);
        }
        catch { }
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        try
        {
            while (!ct.IsCancellationRequested && _running)
            {
                await Diagnostics.DetectorScanScope.RunAsync(_scopeFactory, nameof(HeapSprayDetector), () => ScanOnceAsync(ct));
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
                CheckUniformSizeAndAlert(pid, procName, regions, totalBytes, now, ct);
                return;
            }

            double avgEntropy = await CalculateAverageEntropyAsync(handle, regions);

            bool fired = false;

            var entropyVerdict = Detection.Heuristics.HeapSprayHeuristics.EvaluateEntropy(totalBytes, avgEntropy);
            if (entropyVerdict is not null)
            {
                string reason = entropyVerdict.Reason;
                int severity = entropyVerdict.Severity;

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

                await PersistAsync(alert, ct).ConfigureAwait(false);
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
        var verdict = Detection.Heuristics.HeapSprayHeuristics.EvaluateUniformSizes(
            regions.Select(r => r.size).ToList());

        if (verdict is not null)
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
                SuspicionReason = verdict.Reason,
                Severity = verdict.Severity,
                DetectedAtUtc = now
            };

            _ = PersistAsync(alert, ct);
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
            if (sampled % 10 == 0)
                await Task.Yield();
        }

        return sampled > 0 ? total / sampled : 0;
    }

    private static double CalculateEntropy(byte[] data, int length)
        => Detection.Heuristics.HeapSprayHeuristics.CalculateEntropy(data.AsSpan(0, length));

    private static bool IsSystemProcess(string procName)
        => Detection.Heuristics.HeapSprayHeuristics.IsSystemProcess(procName);
}
