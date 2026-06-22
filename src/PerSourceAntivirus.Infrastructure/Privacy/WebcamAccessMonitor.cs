using System.Runtime.Versioning;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Privacy;

[SupportedOSPlatform("windows")]
public sealed class WebcamAccessMonitor : IWebcamAccessMonitor
{
    private readonly IWebcamAccessRepository _repository;
    private volatile bool _running;
    private readonly Dictionary<string, long> _lastSeenStartTimes = new(StringComparer.OrdinalIgnoreCase);

    private const string WebcamNonPackagedKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged";

    public event EventHandler<WebcamAccessEventArgs>? AlertDetected;

    public WebcamAccessMonitor(IWebcamAccessRepository repository)
    {
        _repository = repository;
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        InitializeBaseline();

        try
        {
            while (!ct.IsCancellationRequested && _running)
            {
                try
                {
                    ScanWebcamRegistry();
                }
                catch { }
                await Task.Delay(TimeSpan.FromSeconds(10), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private void InitializeBaseline()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(WebcamNonPackagedKey);
            if (key is null)
                return;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                using var subKey = key.OpenSubKey(subKeyName);
                if (subKey is null)
                    continue;
                var startTime = subKey.GetValue("LastUsedTimeStart");
                if (startTime is long startTimeLong)
                    _lastSeenStartTimes[subKeyName] = startTimeLong;
            }
        }
        catch { }
    }

    private void ScanWebcamRegistry()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(WebcamNonPackagedKey);
            if (key is null)
                return;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                using var subKey = key.OpenSubKey(subKeyName);
                if (subKey is null)
                    continue;

                var startTimeObj = subKey.GetValue("LastUsedTimeStart");
                if (startTimeObj is not long startTimeLong)
                    continue;

                if (_lastSeenStartTimes.TryGetValue(subKeyName, out var previous) && previous == startTimeLong)
                    continue;

                _lastSeenStartTimes[subKeyName] = startTimeLong;

                var processName = ExtractProcessName(subKeyName);

                var accessEvent = new WebcamAccessEvent
                {
                    Id = Guid.NewGuid(),
                    ProcessName = processName,
                    ProcessId = 0,
                    DevicePath = "webcam",
                    AccessType = "Open",
                    WasBlocked = false,
                    Severity = 5,
                    DetectedAtUtc = DateTime.UtcNow
                };

                try { _repository.AddAsync(accessEvent).GetAwaiter().GetResult(); } catch { }
                AlertDetected?.Invoke(this, new WebcamAccessEventArgs(accessEvent));
            }
        }
        catch { }
    }

    private static string ExtractProcessName(string subKeyName)
    {
        var lastBackslash = subKeyName.LastIndexOf('\\');
        var fileName = lastBackslash >= 0 ? subKeyName[(lastBackslash + 1)..] : subKeyName;
        var dotExe = fileName.LastIndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return dotExe >= 0 ? fileName[..(dotExe + 4)] : fileName;
    }
}
