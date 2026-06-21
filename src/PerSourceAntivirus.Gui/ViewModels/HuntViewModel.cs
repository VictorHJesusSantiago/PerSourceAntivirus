using System.Collections.ObjectModel;
using System.Windows.Input;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Gui.ViewModels;

public class HuntViewModel : ViewModelBase
{
    private readonly IHuntQueryService _huntService;
    private string _processName = string.Empty;
    private string _filePath = string.Empty;
    private string _ipAddress = string.Empty;
    private string _registryKey = string.Empty;
    private string _hash = string.Empty;
    private string _status = string.Empty;
    private bool _isLoading;

    public string ProcessName { get => _processName; set => Set(ref _processName, value); }
    public string FilePath    { get => _filePath;    set => Set(ref _filePath,    value); }
    public string IpAddress   { get => _ipAddress;   set => Set(ref _ipAddress,   value); }
    public string RegistryKey { get => _registryKey; set => Set(ref _registryKey, value); }
    public string Hash        { get => _hash;        set => Set(ref _hash,        value); }
    public string Status      { get => _status;      private set => Set(ref _status, value); }
    public bool   IsLoading   { get => _isLoading;   private set => Set(ref _isLoading, value); }

    public ObservableCollection<ProcessCreationEvent> Processes { get; } = [];
    public ObservableCollection<FileActivityEvent>    Files     { get; } = [];
    public ObservableCollection<RegistryActivityEvent> Registry { get; } = [];
    public ObservableCollection<NetworkConnectionEvent> Network { get; } = [];

    public ICommand SearchCommand { get; }
    public ICommand ClearCommand  { get; }

    public HuntViewModel(IHuntQueryService huntService)
    {
        _huntService  = huntService;
        SearchCommand = new RelayCommand(async () => await SearchAsync());
        ClearCommand  = new RelayCommand(Clear);
    }

    private async Task SearchAsync()
    {
        IsLoading = true;
        Status = "Buscando...";
        Processes.Clear(); Files.Clear(); Registry.Clear(); Network.Clear();
        try
        {
            var filters = new HuntQueryFilters(
                ProcessId:   null,
                ProcessName: Null(_processName),
                FilePath:    Null(_filePath),
                RegistryKey: Null(_registryKey),
                IpAddress:   Null(_ipAddress),
                Port:        null,
                Hash:        Null(_hash),
                From:        null,
                To:          null);

            var results = await _huntService.QueryAsync(filters);

            foreach (var p in results.Processes) Processes.Add(p);
            foreach (var f in results.Files)     Files.Add(f);
            foreach (var r in results.Registry)  Registry.Add(r);
            foreach (var n in results.Network)   Network.Add(n);

            Status = $"{results.TotalCount} resultado(s) — " +
                     $"{results.Processes.Count} processos, {results.Files.Count} arquivos, " +
                     $"{results.Registry.Count} registro, {results.Network.Count} rede.";
        }
        catch (Exception ex) { Status = $"Erro: {ex.Message}"; }
        finally { IsLoading = false; }
    }

    private void Clear()
    {
        ProcessName = FilePath = IpAddress = RegistryKey = Hash = string.Empty;
        Processes.Clear(); Files.Clear(); Registry.Clear(); Network.Clear();
        Status = string.Empty;
    }

    private static string? Null(string s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
