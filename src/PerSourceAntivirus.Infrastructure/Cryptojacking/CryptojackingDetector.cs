using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Cryptojacking;

// Correlates sustained high CPU usage with outbound TCP connections to well-known
// cryptocurrency mining pool ports (Stratum protocol and common XMR/ETH pool ports).
[SupportedOSPlatform("windows")]
public sealed class CryptojackingDetector : ICryptojackingDetector
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ConcurrentDictionary<int, TimeSpan> _lastCpuTime = new();
    private readonly ConcurrentDictionary<int, DateTime> _lastSampleAt = new();
    private readonly ConcurrentDictionary<int, DateTime> _alerted = new();
    private volatile bool _running;

    private static readonly HashSet<int> MiningPoolPorts = new()
    {
        3333, 3334, 3335, 3336, 4444, 5555, 5556, 7777, 8080, 8888,
        9999, 14444, 14433, 45700, 4028, 3032, 1800, 8118, 20535
    };

    public event EventHandler<CryptojackingAlertEventArgs>? AlertDetected;

    public CryptojackingDetector(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    private async Task PersistAsync(CryptojackingAlert alert, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<ICryptojackingAlertRepository>();
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
                await Diagnostics.DetectorScanScope.RunAsync(_scopeFactory, nameof(CryptojackingDetector), () => ScanOnceAsync(ct));
                await Task.Delay(TimeSpan.FromSeconds(20), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private async Task ScanOnceAsync(CancellationToken ct)
    {
        Dictionary<int, List<(string address, int port)>> connectionsByPid;
        try { connectionsByPid = TcpTableReader.GetTcpConnectionsByPid(); }
        catch (Exception) { return; }

        SysProcess[] processes;
        try { processes = SysProcess.GetProcesses(); }
        catch (Exception) { return; }

        var now = DateTime.UtcNow;
        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            try { await EvaluateProcessAsync(proc, connectionsByPid, now, ct); }
            catch (Exception) { }
            finally { proc.Dispose(); }
        }
    }

    private async Task EvaluateProcessAsync(
        SysProcess proc,
        Dictionary<int, List<(string address, int port)>> connectionsByPid,
        DateTime now,
        CancellationToken ct)
    {
        int pid;
        string procName;
        TimeSpan totalCpu;
        try
        {
            pid = proc.Id;
            procName = proc.ProcessName;
            totalCpu = proc.TotalProcessorTime;
        }
        catch (Exception) { return; }

        if (pid <= 4) return;

        double cpuPercent = 0;
        if (_lastCpuTime.TryGetValue(pid, out var prevCpu) && _lastSampleAt.TryGetValue(pid, out var prevAt))
        {
            var elapsedWall = (now - prevAt).TotalMilliseconds * Environment.ProcessorCount;
            var elapsedCpu = (totalCpu - prevCpu).TotalMilliseconds;
            if (elapsedWall > 0) cpuPercent = Math.Max(0, Math.Min(100, elapsedCpu / elapsedWall * 100));
        }
        _lastCpuTime[pid] = totalCpu;
        _lastSampleAt[pid] = now;

        connectionsByPid.TryGetValue(pid, out var connections);
        var poolConnection = connections?.FirstOrDefault(c => MiningPoolPorts.Contains(c.port));
        bool hasPoolPort = poolConnection is { address.Length: > 0 };
        bool sustainedHighCpu = cpuPercent >= 80.0;

        if (!hasPoolPort && !sustainedHighCpu) return;

        string reason;
        int severity;
        if (hasPoolPort && sustainedHighCpu) { reason = "MiningPoolPortAndHighCpu"; severity = 9; }
        else if (hasPoolPort) { reason = "MiningPoolPort"; severity = 6; }
        else { return; } // High CPU alone is too noisy without a corroborating network signal

        if (_alerted.TryGetValue(pid, out var last) && (now - last).TotalMinutes < 10) return;
        _alerted[pid] = now;

        var alert = new CryptojackingAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = procName,
            ProcessId = pid,
            CpuPercent = Math.Round(cpuPercent, 1),
            RemoteAddress = poolConnection?.address,
            RemotePort = poolConnection?.port ?? 0,
            DetectionReason = reason,
            Severity = severity,
            DetectedAtUtc = now
        };

        await PersistAsync(alert, ct).ConfigureAwait(false);
        AlertDetected?.Invoke(this, new CryptojackingAlertEventArgs(alert));
    }
}

[SupportedOSPlatform("windows")]
internal static class TcpTableReader
{
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, int tblClass, int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort; // network byte order in the low bytes
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    public static Dictionary<int, List<(string address, int port)>> GetTcpConnectionsByPid()
    {
        var result = new Dictionary<int, List<(string, int)>>();
        int bufSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufSize <= 0) return result;

        IntPtr buffer = Marshal.AllocHGlobal(bufSize);
        try
        {
            int ret = GetExtendedTcpTable(buffer, ref bufSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return result;

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(IntPtr.Add(rowPtr, i * rowSize));
                int pid = (int)row.owningPid;
                if (pid <= 0) continue;

                var addr = new IPAddress(row.remoteAddr).ToString();
                int port = ((int)row.remotePort & 0xFF) << 8 | (((int)row.remotePort >> 8) & 0xFF);
                if (port == 0) continue;

                if (!result.TryGetValue(pid, out var list))
                {
                    list = new List<(string, int)>();
                    result[pid] = list;
                }
                list.Add((addr, port));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }
}
