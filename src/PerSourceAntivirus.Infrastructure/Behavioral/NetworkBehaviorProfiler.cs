using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Behavioral;

[SupportedOSPlatform("windows")]
public sealed class NetworkBehaviorProfiler : INetworkBehaviorProfiler
{
    private const int LearningThreshold = 10;
    private const int MaxBaselineEntries = 50;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwSize, bool bOrder,
        int ulAf, int tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ConcurrentDictionary<string, NetworkBehaviorProfile> _cache = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _cts;

    public event EventHandler<NetworkBehaviorAlertEventArgs>? AlertDetected;

    public NetworkBehaviorProfiler(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        await LoadProfilesFromDbAsync(ct);

        await Task.Run(() => PollLoopAsync(_cts.Token), _cts.Token).ConfigureAwait(false);
    }

    public void StopMonitoring() => _cts?.Cancel();

    public async Task<NetworkBehaviorProfile?> GetProfileAsync(string processName, CancellationToken ct = default)
    {
        if (_cache.TryGetValue(processName, out var cached))
            return cached;

        using var scope = _scopeFactory.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<INetworkBehaviorProfileRepository>();
        return await repo.GetByProcessNameAsync(processName, ct);
    }

    private async Task LoadProfilesFromDbAsync(CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repo = scope.ServiceProvider.GetRequiredService<INetworkBehaviorProfileRepository>();
            var profiles = await repo.GetAllAsync(ct);
            foreach (var p in profiles)
                _cache[p.ProcessName] = p;
        }
        catch { }
    }

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var connections = GetTcpConnections();
                foreach (var (remoteIp, remotePort, pid) in connections)
                {
                    if (ct.IsCancellationRequested)
                        break;
                    await ProcessConnectionAsync(remoteIp, remotePort, pid, ct);
                }
            }
            catch { }

            await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
        }
    }

    private async Task ProcessConnectionAsync(string remoteIp, int remotePort, int pid, CancellationToken ct)
    {
        string procName;
        try
        {
            using var proc = SysProcess.GetProcessById(pid);
            procName = proc.ProcessName;
        }
        catch { return; }

        if (string.IsNullOrEmpty(procName))
            return;

        var now = DateTime.UtcNow;

        if (!_cache.TryGetValue(procName, out var profile))
        {
            profile = new NetworkBehaviorProfile
            {
                Id = Guid.NewGuid(),
                ProcessName = procName,
                BaselineIps = string.Empty,
                BaselinePorts = string.Empty,
                ObservationCount = 0,
                FirstSeenAtUtc = now,
                LastUpdatedAtUtc = now
            };
            _cache[procName] = profile;
        }

        if (profile.ObservationCount < LearningThreshold)
        {
            UpdateBaseline(profile, remoteIp, remotePort, now);

            try
            {
                using var scope = _scopeFactory.CreateScope();
                var profileRepo = scope.ServiceProvider.GetRequiredService<INetworkBehaviorProfileRepository>();
                await profileRepo.AddOrUpdateAsync(profile, ct);
            }
            catch { }

            return;
        }

        var baselineIps = SplitSet(profile.BaselineIps);
        var baselinePorts = SplitSet(profile.BaselinePorts);

        var ipAnomaly = !string.IsNullOrEmpty(remoteIp) && !baselineIps.Contains(remoteIp);
        var portAnomaly = remotePort > 0 && !baselinePorts.Contains(remotePort.ToString());

        if (!ipAnomaly && !portAnomaly)
            return;

        var reason = ipAnomaly && portAnomaly
            ? $"Unexpected IP {remoteIp} and port {remotePort}"
            : ipAnomaly
                ? $"Unexpected remote IP {remoteIp}"
                : $"Unexpected remote port {remotePort}";

        var alert = new NetworkBehaviorAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = procName,
            ProcessId = pid,
            UnexpectedIp = remoteIp,
            UnexpectedPort = remotePort,
            AnomalyReason = reason,
            Severity = 6,
            DetectedAtUtc = now
        };

        try
        {
            using var scope = _scopeFactory.CreateScope();
            var alertRepo = scope.ServiceProvider.GetRequiredService<INetworkBehaviorAlertRepository>();
            await alertRepo.AddAsync(alert, ct);
        }
        catch { }

        AlertDetected?.Invoke(this, new NetworkBehaviorAlertEventArgs(alert));
    }

    private static void UpdateBaseline(NetworkBehaviorProfile profile, string ip, int port, DateTime now)
    {
        if (!string.IsNullOrEmpty(ip))
        {
            var ips = SplitList(profile.BaselineIps);
            if (!ips.Contains(ip))
            {
                ips.Add(ip);
                if (ips.Count > MaxBaselineEntries)
                    ips.RemoveAt(0);
                profile.BaselineIps = string.Join(",", ips);
            }
        }

        if (port > 0)
        {
            var ports = SplitList(profile.BaselinePorts);
            var portStr = port.ToString();
            if (!ports.Contains(portStr))
            {
                ports.Add(portStr);
                if (ports.Count > MaxBaselineEntries)
                    ports.RemoveAt(0);
                profile.BaselinePorts = string.Join(",", ports);
            }
        }

        profile.ObservationCount++;
        profile.LastUpdatedAtUtc = now;
    }

    private static HashSet<string> SplitSet(string value)
    {
        if (string.IsNullOrEmpty(value))
            return new HashSet<string>();
        return new HashSet<string>(value.Split(',', StringSplitOptions.RemoveEmptyEntries));
    }

    private static List<string> SplitList(string value)
    {
        if (string.IsNullOrEmpty(value))
            return new List<string>();
        return new List<string>(value.Split(',', StringSplitOptions.RemoveEmptyEntries));
    }

    private static List<(string RemoteIp, int RemotePort, int Pid)> GetTcpConnections()
    {
        var result = new List<(string, int, int)>();

        var size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, 5, 0);
        if (size == 0)
            return result;

        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, true, 2, 5, 0) != 0)
                return result;

            var count = Marshal.ReadInt32(buf);
            var offset = IntPtr.Size == 8 ? 8 : 4;
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(IntPtr.Add(buf, offset + i * rowSize));

                if (row.dwState != 5)
                    continue;

                if (row.dwRemoteAddr == 0)
                    continue;

                string remoteIp;
                try { remoteIp = new IPAddress(row.dwRemoteAddr).ToString(); }
                catch { continue; }

                var remotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwRemotePort);

                result.Add((remoteIp, remotePort, (int)row.dwOwningPid));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }

        return result;
    }
}
