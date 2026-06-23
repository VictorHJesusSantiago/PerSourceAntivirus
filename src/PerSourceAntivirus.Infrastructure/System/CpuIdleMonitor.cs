using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public sealed class CpuIdleMonitor : ICpuIdleMonitor, IDisposable
{
    [DllImport("kernel32.dll")]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS lpSystemPowerStatus);

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public uint BatteryLifeTime;
        public uint BatteryFullLifeTime;
    }

    private volatile bool _isCpuBusy;
    private CancellationTokenSource? _cts;
    private bool _disposed;

    public bool IsCpuBusy => _isCpuBusy;

    public bool IsOnBattery
    {
        get
        {
            GetSystemPowerStatus(out var status);
            return status.ACLineStatus == 0;
        }
    }

    public event EventHandler<bool>? CpuBusyChanged;

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        await Task.Run(() => PollLoopAsync(_cts.Token), _cts.Token).ConfigureAwait(false);
    }

    public void StopMonitoring() => _cts?.Cancel();

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var usage = await ReadCpuUsageAsync(ct);
                var busy = usage > 20f;

                if (busy != _isCpuBusy)
                {
                    _isCpuBusy = busy;
                    CpuBusyChanged?.Invoke(this, busy);
                }
            }
            catch { }

            try { await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private static async Task<float> ReadCpuUsageAsync(CancellationToken ct)
    {
        try
        {
            using var counter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            counter.NextValue();
            await Task.Delay(1000, ct).ConfigureAwait(false);
            return counter.NextValue();
        }
        catch
        {
            return 0f;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts?.Cancel();
        _cts?.Dispose();
    }
}
