using System.IO;
using System.Text.Json;
using System.Windows.Input;
using Microsoft.Extensions.Configuration;
using PerSourceAntivirus.Gui.Services;

namespace PerSourceAntivirus.Gui.ViewModels;

public class SettingsViewModel : ViewModelBase
{
    private readonly IConfiguration _config;
    private readonly SafeModeScanScheduler _scheduler;
    private string _yaraRulesDirectory = string.Empty;
    private bool _realtimeProtectionEnabled;
    private string _quarantineDirectory = string.Empty;
    private int _scanMaxParallelism = 4;
    private bool _dnsSinkholeEnabled;
    private string _siemProtocol = "None";

    public string YaraRulesDirectory
    {
        get => _yaraRulesDirectory;
        set => Set(ref _yaraRulesDirectory, value);
    }

    public bool RealtimeProtectionEnabled
    {
        get => _realtimeProtectionEnabled;
        set => Set(ref _realtimeProtectionEnabled, value);
    }

    public string QuarantineDirectory
    {
        get => _quarantineDirectory;
        set => Set(ref _quarantineDirectory, value);
    }

    public int ScanMaxParallelism
    {
        get => _scanMaxParallelism;
        set => Set(ref _scanMaxParallelism, value);
    }

    public bool DnsSinkholeEnabled
    {
        get => _dnsSinkholeEnabled;
        set => Set(ref _dnsSinkholeEnabled, value);
    }

    public string SiemProtocol
    {
        get => _siemProtocol;
        set => Set(ref _siemProtocol, value);
    }

    public string SaveMessage { get => _saveMessage; private set => Set(ref _saveMessage, value); }
    private string _saveMessage = string.Empty;

    public string RebootScanStatus { get => _rebootScanStatus; private set => Set(ref _rebootScanStatus, value); }
    private string _rebootScanStatus = string.Empty;

    public ICommand SaveCommand { get; }
    public ICommand ScheduleRebootScanCommand { get; }

    public SettingsViewModel(IConfiguration config, SafeModeScanScheduler scheduler)
    {
        _config = config;
        _scheduler = scheduler;
        LoadFromConfig();
        SaveCommand = new RelayCommand(SaveToFile);
        ScheduleRebootScanCommand = new RelayCommand(ScheduleRebootScan);

        if (_scheduler.IsScanScheduled())
            _rebootScanStatus = "Reboot scan is already scheduled.";
    }

    private void LoadFromConfig()
    {
        _yaraRulesDirectory = _config["Yara:RulesDirectory"] ?? string.Empty;
        _realtimeProtectionEnabled = bool.TryParse(_config["RealtimeProtection:Enabled"], out var rt) && rt;
        _quarantineDirectory = _config["Quarantine:Directory"] ?? string.Empty;
        _scanMaxParallelism = int.TryParse(_config["Scanning:MaxParallelism"], out var mp) ? mp : 4;
        _dnsSinkholeEnabled = bool.TryParse(_config["Dns:SinkholeEnabled"], out var dns) && dns;
        _siemProtocol = _config["Siem:Protocol"] ?? "None";
    }

    private void SaveToFile()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
            Dictionary<string, object> root;

            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                root = JsonSerializer.Deserialize<Dictionary<string, object>>(json) ?? [];
            }
            else
            {
                root = [];
            }

            root["Yara"] = new { RulesDirectory = _yaraRulesDirectory };
            root["RealtimeProtection"] = new { Enabled = _realtimeProtectionEnabled };
            root["Quarantine"] = new { Directory = _quarantineDirectory };
            root["Scanning"] = new { MaxParallelism = _scanMaxParallelism };
            root["Dns"] = new { SinkholeEnabled = _dnsSinkholeEnabled };
            root["Siem"] = new { Protocol = _siemProtocol };

            File.WriteAllText(path, JsonSerializer.Serialize(root, new JsonSerializerOptions { WriteIndented = true }));
            SaveMessage = "Settings saved.";
        }
        catch (Exception ex)
        {
            SaveMessage = $"Error: {ex.Message}";
        }
    }

    private void ScheduleRebootScan()
    {
        var result = _scheduler.ScheduleRebootScan();
        RebootScanStatus = result ? "Reboot scan scheduled successfully." : "Failed to schedule reboot scan (requires admin).";
    }
}
