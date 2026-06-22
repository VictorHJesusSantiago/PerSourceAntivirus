using System.Collections.Concurrent;
using System.Runtime.Versioning;
using PacketDotNet;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class ArpSpoofingDetector(IArpSpoofingAlertRepository repository) : IArpSpoofingDetector
{
    // IP → last seen MAC
    private readonly ConcurrentDictionary<string, string> _ipToMac = new(StringComparer.OrdinalIgnoreCase);
    // IP → list of (MAC, timestamp) seen in last minute
    private readonly ConcurrentDictionary<string, List<(string mac, DateTime seen)>> _recentMacs = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private volatile bool _running;

    public event EventHandler<ArpSpoofingAlertEventArgs>? AlertDetected;

    public async Task StartMonitoringAsync(string? deviceName, CancellationToken ct)
    {
        _running = true;
        ILiveDevice? device = null;
        try
        {
            device = GetDevice(deviceName);
            if (device is null) return;

            device.OnPacketArrival += OnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);
            device.Filter = "arp";  // BPF filter: only ARP packets
            device.StartCapture();

            while (_running && !ct.IsCancellationRequested)
                await Task.Delay(1000, ct).ConfigureAwait(false);
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
            var arp = packet.Extract<ArpPacket>();
            if (arp is null) return;

            var senderIp  = arp.SenderProtocolAddress.ToString();
            var senderMac = arp.SenderHardwareAddress.ToString();
            var targetIp  = arp.TargetProtocolAddress.ToString();

            if (string.IsNullOrEmpty(senderIp) || senderIp == "0.0.0.0") return;

            var now = DateTime.UtcNow;

            // Track recent MACs for this IP
            var macList = _recentMacs.GetOrAdd(senderIp, _ => []);
            lock (macList)
            {
                macList.RemoveAll(m => (now - m.seen).TotalMinutes > 1);
                if (!macList.Any(m => m.mac == senderMac))
                    macList.Add((senderMac, now));

                // Multiple MACs for same IP in 1 min = spoofing
                if (macList.Count > 1)
                {
                    FireAlert(senderMac, senderIp,
                        macList.First(m => m.mac != senderMac).mac,
                        senderMac, "MultipleArpReplies", macList.Count);
                }
            }

            // Gratuitous ARP: sender IP == target IP
            if (senderIp == targetIp && _ipToMac.TryGetValue(senderIp, out var knownMac) && knownMac != senderMac)
            {
                FireAlert(senderMac, senderIp, knownMac, senderMac, "GratuitousArp", 1);
            }

            // MAC conflict: known MAC for this IP differs
            if (_ipToMac.TryGetValue(senderIp, out var previousMac) && previousMac != senderMac)
            {
                FireAlert(senderMac, senderIp, previousMac, senderMac, "MacConflict", 1);
            }

            _ipToMac[senderIp] = senderMac;
        }
        catch { }
    }

    private void FireAlert(string attackerMac, string victimIp, string legitimateMac,
        string spoofedMac, string reason, int count)
    {
        var key = $"{attackerMac}_{victimIp}_{reason}";
        var now = DateTime.UtcNow;
        if (_recentAlerts.TryGetValue(key, out var last) && (now - last).TotalMinutes < 5) return;
        _recentAlerts[key] = now;

        var alert = new ArpSpoofingAlert
        {
            Id = Guid.NewGuid(),
            AttackerMac = attackerMac,
            VictimIp = victimIp,
            LegitimateKnownMac = legitimateMac,
            SpoofedMac = spoofedMac,
            DetectionReason = reason,
            DuplicateCount = count,
            Severity = 8,
            DetectedAtUtc = now
        };

        try { repository.AddAsync(alert).GetAwaiter().GetResult(); } catch { }
        AlertDetected?.Invoke(this, new ArpSpoofingAlertEventArgs(alert));
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
