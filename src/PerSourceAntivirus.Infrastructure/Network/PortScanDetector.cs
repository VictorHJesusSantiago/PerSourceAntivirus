using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PacketDotNet;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class PortScanDetector(IServiceScopeFactory scopeFactory) : IPortScanDetector
{
    // sourceIp -> bag of (port, time)
    private readonly ConcurrentDictionary<string, ConcurrentBag<(int port, DateTime time)>> _portTracker =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _running;

    public event EventHandler<PortScanAlertEventArgs>? AlertDetected;

    private const string BpfFilter = "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) = 0";
    private const int PortThreshold = 10;
    private const double WindowSeconds = 1.0;
    private const double DedupMinutes = 5.0;

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        ILiveDevice? device = null;
        try
        {
            device = GetDevice(null);
            if (device is null) return;

            device.OnPacketArrival += OnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);
            device.Filter = BpfFilter;
            device.StartCapture();

            while (_running && !ct.IsCancellationRequested)
                await Task.Delay(500, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        finally
        {
            if (device is not null)
            {
                try { device.StopCapture(); } catch { }
                device.OnPacketArrival -= OnPacketArrival;
                device.Close();
            }
            _running = false;
        }
    }

    public void StopMonitoring() => _running = false;

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var raw = e.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var ip = packet.Extract<IPPacket>();
            var tcp = packet.Extract<TcpPacket>();
            if (ip is null || tcp is null) return;

            var sourceIp = ip.SourceAddress.ToString();
            var destPort = tcp.DestinationPort;
            var now = DateTime.UtcNow;

            var bag = _portTracker.GetOrAdd(sourceIp, _ => new ConcurrentBag<(int, DateTime)>());
            bag.Add((destPort, now));

            // Check for scan: distinct ports within the time window
            var windowStart = now.AddSeconds(-WindowSeconds);
            var recentEntries = bag
                .Where(x => x.time >= windowStart)
                .ToList();

            var distinctPorts = recentEntries
                .Select(x => x.port)
                .Distinct()
                .ToList();

            if (distinctPorts.Count > PortThreshold)
            {
                var windowMs = (now - recentEntries.Min(x => x.time)).TotalMilliseconds;
                FireAlert(sourceIp, distinctPorts, recentEntries.Count, windowMs);
            }

            // Periodically prune stale entries to avoid memory growth
            if (bag.Count > 10000)
                _portTracker.TryRemove(sourceIp, out _);
        }
        catch { }
    }

    private void FireAlert(string sourceIp, List<int> ports, int connectionCount, double windowMs)
    {
        var now = DateTime.UtcNow;
        if (_recentAlerts.TryGetValue(sourceIp, out var last) && (now - last).TotalMinutes < DedupMinutes) return;
        _recentAlerts[sourceIp] = now;

        var alert = new PortScanAlert
        {
            Id = Guid.NewGuid(),
            SourceIp = sourceIp,
            TargetPorts = string.Join(",", ports.OrderBy(p => p)),
            ConnectionCount = connectionCount,
            TimeWindowMs = windowMs,
            DetectionMethod = "SharpPcap-SYN",
            Severity = 8,
            DetectedAtUtc = now
        };

        _ = PersistAsync(alert);
        AlertDetected?.Invoke(this, new PortScanAlertEventArgs(alert));
    }

    // Per-write scope: AppDbContext is not thread-safe; these run on capture-callback threads.
    private async Task PersistAsync(PortScanAlert alert)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IPortScanAlertRepository>();
            await repository.AddAsync(alert).ConfigureAwait(false);
        }
        catch { }
    }

    private static ILiveDevice? GetDevice(string? deviceName)
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0) return null;
            if (deviceName is not null)
                return devices.FirstOrDefault(d => d.Name == deviceName);
            return devices[0];
        }
        catch { return null; }
    }
}
