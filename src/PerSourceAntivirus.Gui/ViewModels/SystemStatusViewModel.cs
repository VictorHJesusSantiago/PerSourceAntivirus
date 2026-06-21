using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Gui.ViewModels;

public class SystemStatusViewModel : ViewModelBase
{
    private readonly ICpuIdleMonitor _cpu;
    private readonly IGamingModeDetector _gaming;
    private bool _isCpuBusy;
    private bool _isGamingMode;
    private bool _isOnBattery;

    public bool IsCpuBusy { get => _isCpuBusy; private set => Set(ref _isCpuBusy, value); }
    public bool IsGamingMode { get => _isGamingMode; private set => Set(ref _isGamingMode, value); }
    public bool IsOnBattery { get => _isOnBattery; private set => Set(ref _isOnBattery, value); }

    public string CpuStatusText => IsCpuBusy ? "CPU Busy" : "CPU Idle";
    public string GamingModeText => IsGamingMode ? "Gaming Mode Active" : "Gaming Mode Off";
    public string BatteryStatusText => IsOnBattery ? "On Battery" : "Plugged In";

    public string CpuStatusColor => IsCpuBusy ? "#FFB24A" : "#4AFF8A";
    public string GamingStatusColor => IsGamingMode ? "#FFB24A" : "#4AFF8A";
    public string BatteryStatusColor => IsOnBattery ? "#FFB24A" : "#4AFF8A";

    public SystemStatusViewModel(ICpuIdleMonitor cpu, IGamingModeDetector gaming)
    {
        _cpu = cpu;
        _gaming = gaming;

        _isCpuBusy = _cpu.IsCpuBusy;
        _isOnBattery = _cpu.IsOnBattery;
        _isGamingMode = _gaming.IsGamingModeActive;

        _cpu.CpuBusyChanged += (_, busy) =>
        {
            IsCpuBusy = busy;
            IsOnBattery = _cpu.IsOnBattery;
            Notify(nameof(CpuStatusText));
            Notify(nameof(BatteryStatusText));
            Notify(nameof(CpuStatusColor));
            Notify(nameof(BatteryStatusColor));
        };

        _gaming.GamingModeChanged += (_, active) =>
        {
            IsGamingMode = active;
            Notify(nameof(GamingModeText));
            Notify(nameof(GamingStatusColor));
        };
    }
}
