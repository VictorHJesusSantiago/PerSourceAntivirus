using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public sealed partial class UsbDeviceControlService : IUsbDeviceControlService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly HashSet<string> _allowedVendorProductIds;
    private ManagementEventWatcher? _watcher;

    public event EventHandler<UsbDeviceEventArgs>? DeviceEvent;

    [GeneratedRegex(@"VID_[0-9A-F]{4}&PID_[0-9A-F]{4}", RegexOptions.IgnoreCase)]
    private static partial Regex VidPidRegex();

    public UsbDeviceControlService(IServiceScopeFactory scopeFactory, string allowlistFile)
    {
        _scopeFactory = scopeFactory;
        _allowedVendorProductIds = LoadAllowlist(allowlistFile);
    }

    private static HashSet<string> LoadAllowlist(string allowlistFile)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(allowlistFile)) return set;

        foreach (var line in File.ReadAllLines(allowlistFile))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
            set.Add(trimmed.ToUpperInvariant());
        }
        return set;
    }

    private async Task PersistAsync(UsbDeviceEvent evt, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IUsbDeviceEventRepository>();
            await repository.AddAsync(evt, ct).ConfigureAwait(false);
        }
        catch { }
    }

    public Task StartMonitoringAsync(CancellationToken ct)
    {
        _watcher = new ManagementEventWatcher(
            "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_PnPEntity'");

        _watcher.EventArrived += (_, e) =>
        {
            try { OnDeviceArrived(e, ct); }
            catch { }
        };

        _watcher.Start();
        ct.Register(() => { try { _watcher?.Stop(); _watcher?.Dispose(); } catch { } });
        return Task.CompletedTask;
    }

    public void StopMonitoring()
    {
        try { _watcher?.Stop(); _watcher?.Dispose(); }
        catch { }
        _watcher = null;
    }

    private void OnDeviceArrived(EventArrivedEventArgs e, CancellationToken ct)
    {
        var instance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
        var deviceId = (string)(instance["DeviceID"] ?? string.Empty);
        var description = (string)(instance["Description"] ?? instance["Name"] ?? "Unknown device");

        if (!deviceId.StartsWith("USB", StringComparison.OrdinalIgnoreCase)) return;

        var match = VidPidRegex().Match(deviceId);
        var vidPid = match.Success ? match.Value.ToUpperInvariant() : null;

        bool allowed = vidPid is not null && _allowedVendorProductIds.Contains(vidPid);
        string action;

        if (allowed || _allowedVendorProductIds.Count == 0)
        {
            action = "Allowed";
        }
        else
        {
            action = TryDisableDevice(deviceId) ? "DisabledUnauthorized" : "DisableFailed";
        }

        var evt = new UsbDeviceEvent
        {
            Id = Guid.NewGuid(),
            PnpDeviceId = deviceId,
            Description = description,
            VendorProductId = vidPid,
            WasAllowed = allowed,
            ActionTaken = action,
            DetectedAtUtc = DateTime.UtcNow
        };

        _ = PersistAsync(evt, ct);
        DeviceEvent?.Invoke(this, new UsbDeviceEventArgs(evt));
    }

    private static bool TryDisableDevice(string deviceInstanceId)
    {
        try
        {
            var psi = new ProcessStartInfo("pnputil.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("/disable-device");
            psi.ArgumentList.Add(deviceInstanceId);
            using var process = System.Diagnostics.Process.Start(psi);
            if (process is null) return false;
            process.WaitForExit(10000);
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
