using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class GeoIpEnforcementDetector : IGeoIpEnforcementDetector
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly INetworkMonitor _networkMonitor;
    private readonly IGeoIpBlockingService _geoIp;
    private readonly IWfpBlocker _wfpBlocker;
    private readonly ConcurrentDictionary<string, DateTime> _alerted = new();
    private volatile bool _running;

    public event EventHandler<GeoIpBlockAlertEventArgs>? AlertDetected;

    public GeoIpEnforcementDetector(
        IServiceScopeFactory scopeFactory,
        INetworkMonitor networkMonitor,
        IGeoIpBlockingService geoIp,
        IWfpBlocker wfpBlocker)
    {
        _scopeFactory = scopeFactory;
        _networkMonitor = networkMonitor;
        _geoIp = geoIp;
        _wfpBlocker = wfpBlocker;
    }

    private async Task PersistAsync(GeoIpBlockAlert alert, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IGeoIpBlockAlertRepository>();
            await repository.AddAsync(alert, ct).ConfigureAwait(false);
        }
        catch { }
    }

    public async Task StartMonitoringAsync(string? deviceName, CancellationToken ct)
    {
        if (_geoIp.BlockedCountries.Count == 0) return;

        _running = true;
        try
        {
            while (_running && !ct.IsCancellationRequested)
            {
                try
                {
                    await foreach (var packet in _networkMonitor.CaptureAsync(deviceName, TimeSpan.FromSeconds(15), ct))
                    {
                        try { await EvaluatePacketAsync(packet, ct); }
                        catch (Exception) { }
                    }
                }
                catch (Exception) { }
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private async Task EvaluatePacketAsync(CapturedPacket packet, CancellationToken ct)
    {
        foreach (var (address, direction) in new[]
                 {
                     (packet.DestinationAddress, "Outbound"),
                     (packet.SourceAddress, "Inbound")
                 })
        {
            if (!_geoIp.IsBlockedCountry(address, out var country) || country is null) continue;

            var now = DateTime.UtcNow;
            if (_alerted.TryGetValue(address, out var last) && (now - last).TotalMinutes < 30) continue;
            _alerted[address] = now;

            await _wfpBlocker.AddBlockAsync(address, $"GeoIP block ({country})", ct).ConfigureAwait(false);

            var alert = new GeoIpBlockAlert
            {
                Id = Guid.NewGuid(),
                RemoteAddress = address,
                CountryCode = country,
                Direction = direction,
                Severity = 6,
                DetectedAtUtc = now
            };

            await PersistAsync(alert, ct).ConfigureAwait(false);
            AlertDetected?.Invoke(this, new GeoIpBlockAlertEventArgs(alert));
        }
    }
}
