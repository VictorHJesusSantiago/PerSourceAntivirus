using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

// Device control: watches for newly-plugged USB devices via WMI and disables (via pnputil)
// any device whose VID:PID is not present in the administrator-configured allowlist.
public interface IUsbDeviceControlService
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<UsbDeviceEventArgs> DeviceEvent;
}

public record UsbDeviceEventArgs(UsbDeviceEvent Event);
