using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows.Input;
using Microsoft.Extensions.Configuration;

namespace PerSourceAntivirus.Gui.ViewModels;

public class ExclusionsViewModel : ViewModelBase
{
    private readonly IConfiguration _config;
    private string _newExclusion = string.Empty;

    public ObservableCollection<string> Exclusions { get; } = [];

    public string NewExclusion
    {
        get => _newExclusion;
        set => Set(ref _newExclusion, value);
    }

    public ICommand AddCommand { get; }
    public ICommand RemoveCommand { get; }
    public ICommand ImportCommand { get; }
    public ICommand ExportCommand { get; }

    public ExclusionsViewModel(IConfiguration config)
    {
        _config = config;
        AddCommand = new RelayCommand(AddExclusion);
        RemoveCommand = new RelayCommand<string>(s => { RemoveExclusion(s); return Task.CompletedTask; });
        ImportCommand = new RelayCommand(ImportExclusions);
        ExportCommand = new RelayCommand(ExportExclusions);
        LoadExclusions();
    }

    private void LoadExclusions()
    {
        Exclusions.Clear();
        var paths = _config.GetSection("Scan:ExcludedPaths").GetChildren()
            .Select(c => c.Value ?? string.Empty)
            .Where(v => v.Length > 0);
        foreach (var p in paths)
            Exclusions.Add(p);
    }

    private void AddExclusion()
    {
        var value = _newExclusion.Trim();
        if (string.IsNullOrEmpty(value) || Exclusions.Contains(value))
            return;

        Exclusions.Add(value);
        NewExclusion = string.Empty;
        SaveExclusions();
    }

    private void RemoveExclusion(string item)
    {
        if (Exclusions.Remove(item))
            SaveExclusions();
    }

    private void SaveExclusions()
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

            if (!root.TryGetValue("Scan", out _))
                root["Scan"] = new Dictionary<string, object>();

            root["Scan"] = new { ExcludedPaths = Exclusions.ToArray() };

            File.WriteAllText(path, JsonSerializer.Serialize(root, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    private void ImportExclusions()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
            Title = "Import Exclusions"
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            var lines = File.ReadAllLines(dialog.FileName);
            foreach (var line in lines.Select(l => l.Trim()).Where(l => l.Length > 0))
            {
                if (!Exclusions.Contains(line))
                    Exclusions.Add(line);
            }
            SaveExclusions();
        }
        catch { }
    }

    private void ExportExclusions()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "Text files (*.txt)|*.txt",
            FileName = "exclusions.txt",
            Title = "Export Exclusions"
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            File.WriteAllLines(dialog.FileName, Exclusions);
        }
        catch { }
    }
}
