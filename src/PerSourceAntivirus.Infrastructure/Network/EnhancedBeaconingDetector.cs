using System.Collections.Concurrent;
using System.Runtime.Versioning;
using PacketDotNet;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class EnhancedBeaconingDetector(IBeaconingAnalysisRepository repository) : IEnhancedBeaconingDetector
{
    private readonly ConcurrentDictionary<string, BeaconTracker> _trackers =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts =
        new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _running;

    public event EventHandler<BeaconingAlertEventArgs>? AlertDetected;

    private const string BpfFilter = "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) = 0";
    private const int MinSamples = 5;
    private const int MaxQueueSize = 100;
    private const double DedupMinutes = 5.0;

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

            var dstIp = ip.DestinationAddress.ToString();
            var dstPort = tcp.DestinationPort;
            var payloadSize = tcp.PayloadData?.Length ?? 0;
            var now = DateTime.UtcNow;

            var key = $"{dstIp}:{dstPort}";
            var tracker = _trackers.GetOrAdd(key, _ => new BeaconTracker());

            lock (tracker)
            {
                tracker.ConnectionTimes.Enqueue(now);
                tracker.PayloadSizes.Enqueue(payloadSize);

                while (tracker.ConnectionTimes.Count > MaxQueueSize)
                    tracker.ConnectionTimes.Dequeue();
                while (tracker.PayloadSizes.Count > MaxQueueSize)
                    tracker.PayloadSizes.Dequeue();

                if (tracker.ConnectionTimes.Count >= MinSamples)
                    AnalyzeBeaconing(key, dstIp, dstPort, tracker, now);
            }
        }
        catch { }
    }

    private void AnalyzeBeaconing(string key, string dstIp, int dstPort, BeaconTracker tracker, DateTime now)
    {
        var times = tracker.ConnectionTimes.ToArray();
        var sizes = tracker.PayloadSizes.ToArray();

        if (times.Length < MinSamples) return;

        var diffs = new double[times.Length - 1];
        for (int i = 1; i < times.Length; i++)
            diffs[i - 1] = (times[i] - times[i - 1]).TotalSeconds;

        var avgInterval = diffs.Average();
        if (avgInterval <= 0) return;

        var stdDevDiffs = StandardDeviation(diffs);
        var jitterVariance = stdDevDiffs / avgInterval;

        var sizeDoubles = sizes.Select(s => (double)s).ToArray();
        var payloadSizeVariance = StandardDeviation(sizeDoubles);

        var localTimes = times.Select(t => t.ToLocalTime()).ToArray();
        var isOutsideBusinessHours = localTimes.All(t => t.Hour < 8 || t.Hour >= 18);

        int score = 0;
        if (jitterVariance < 0.15) score += 40;
        if (payloadSizeVariance < 50) score += 30;
        if (isOutsideBusinessHours) score += 30;

        if (score < 50) return;

        var dedupKey = key;
        if (_recentAlerts.TryGetValue(dedupKey, out var last) && (now - last).TotalMinutes < DedupMinutes) return;
        _recentAlerts[dedupKey] = now;

        var analysis = new BeaconingAnalysis
        {
            Id = Guid.NewGuid(),
            DestinationIp = dstIp,
            DestinationPort = dstPort,
            ProcessName = "Unknown",
            ProcessId = 0,
            AverageIntervalSeconds = avgInterval,
            JitterVariance = jitterVariance,
            PayloadSizeVariance = payloadSizeVariance,
            SampleCount = times.Length,
            IsOutsideBusinessHours = isOutsideBusinessHours,
            BeaconingScore = score,
            Severity = 7,
            DetectedAtUtc = now
        };

        try { repository.AddAsync(analysis).GetAwaiter().GetResult(); } catch { }
        AlertDetected?.Invoke(this, new BeaconingAlertEventArgs(analysis));
    }

    private static double StandardDeviation(double[] values)
    {
        if (values.Length == 0) return 0;
        var mean = values.Average();
        var variance = values.Select(v => (v - mean) * (v - mean)).Average();
        return Math.Sqrt(variance);
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

    private sealed class BeaconTracker
    {
        public Queue<DateTime> ConnectionTimes { get; } = new();
        public Queue<int> PayloadSizes { get; } = new();
    }
}
