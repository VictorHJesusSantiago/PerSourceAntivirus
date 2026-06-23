using System.Runtime.Versioning;
using System.Text.Json;
using PerSourceAntivirus.Application.Common.Interfaces;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public sealed class WmiCustomProvider : IWmiCustomProvider
{
    private readonly List<WmiAlertEntry> _alerts = [];
    private CancellationTokenSource? _cts;

    public void PublishThreatAlert(string alertType, string processName, int severity, string details)
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PerSourceAntivirus");
        Directory.CreateDirectory(dir);
        var entry = new WmiAlertEntry(alertType, processName, severity, details, DateTime.UtcNow);
        lock (_alerts)
        {
            _alerts.Add(entry);
            if (_alerts.Count > 1000)
                _alerts.RemoveAt(0);
            try
            {
                File.WriteAllText(
                    Path.Combine(dir, "wmi_alerts.json"),
                    JsonSerializer.Serialize(_alerts));
            }
            catch { }
        }
    }

    public async Task StartAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        await Task.CompletedTask;
    }

    public void Stop()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }
}

internal sealed record WmiAlertEntry(string AlertType, string ProcessName, int Severity, string Details, DateTime Timestamp);
