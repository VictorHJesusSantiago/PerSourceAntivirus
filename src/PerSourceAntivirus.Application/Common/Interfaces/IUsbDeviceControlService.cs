using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IUsbDeviceControlService
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<UsbDeviceEventArgs> DeviceEvent;
}

public record UsbDeviceEventArgs(UsbDeviceEvent Event);
