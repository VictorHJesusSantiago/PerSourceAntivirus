using System.Collections.ObjectModel;
using System.Windows.Input;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Gui.ViewModels;

public record ScanProfileItem(Guid Id, string Name, string ProfileType, string IncludePaths, string ExcludePaths, bool IsDefault);

public class ScanProfilesViewModel : ViewModelBase
{
    private readonly IScanProfileService _profileService;
    private ScanProfileItem? _selectedProfile;
    private string _editName = string.Empty;
    private string _editType = "Quick";
    private string _editIncludePaths = string.Empty;
    private string _editExcludePaths = string.Empty;

    public ObservableCollection<ScanProfileItem> Profiles { get; } = [];

    public ScanProfileItem? SelectedProfile
    {
        get => _selectedProfile;
        set
        {
            Set(ref _selectedProfile, value);
            if (value != null) LoadProfileForEdit(value);
        }
    }

    public string EditName { get => _editName; set => Set(ref _editName, value); }
    public string EditType { get => _editType; set => Set(ref _editType, value); }
    public string EditIncludePaths { get => _editIncludePaths; set => Set(ref _editIncludePaths, value); }
    public string EditExcludePaths { get => _editExcludePaths; set => Set(ref _editExcludePaths, value); }

    public ICommand NewProfileCommand { get; }
    public ICommand SaveProfileCommand { get; }
    public ICommand DeleteProfileCommand { get; }

    public ScanProfilesViewModel(IScanProfileService profileService)
    {
        _profileService = profileService;
        NewProfileCommand = new RelayCommand(NewProfile);
        SaveProfileCommand = new RelayCommand(async () => await SaveProfileAsync());
        DeleteProfileCommand = new RelayCommand(async () => await DeleteProfileAsync());
        _ = LoadProfilesAsync();
    }

    private async Task LoadProfilesAsync()
    {
        try
        {
            var profiles = await _profileService.GetAllAsync();
            Profiles.Clear();
            foreach (var p in profiles)
                Profiles.Add(new ScanProfileItem(p.Id, p.Name, p.ProfileType, p.IncludePaths, p.ExcludePaths, p.IsDefault));
        }
        catch { }
    }

    private void LoadProfileForEdit(ScanProfileItem profile)
    {
        EditName = profile.Name;
        EditType = profile.ProfileType;
        EditIncludePaths = profile.IncludePaths;
        EditExcludePaths = profile.ExcludePaths;
    }

    private void NewProfile()
    {
        SelectedProfile = null;
        EditName = "New Profile";
        EditType = "Quick";
        EditIncludePaths = string.Empty;
        EditExcludePaths = string.Empty;
    }

    private async Task SaveProfileAsync()
    {
        try
        {
            if (_selectedProfile == null)
            {
                var profile = new ScanProfile
                {
                    Id = Guid.NewGuid(),
                    Name = _editName,
                    ProfileType = _editType,
                    IncludePaths = _editIncludePaths,
                    ExcludePaths = _editExcludePaths,
                    FileExtensions = string.Empty,
                    MaxFileSizeBytes = 100 * 1024 * 1024,
                    IsDefault = false,
                    CreatedAtUtc = DateTime.UtcNow
                };
                await _profileService.AddAsync(profile);
            }
            else
            {
                var profile = new ScanProfile
                {
                    Id = _selectedProfile.Id,
                    Name = _editName,
                    ProfileType = _editType,
                    IncludePaths = _editIncludePaths,
                    ExcludePaths = _editExcludePaths,
                    FileExtensions = string.Empty,
                    MaxFileSizeBytes = 100 * 1024 * 1024,
                    IsDefault = _selectedProfile.IsDefault,
                    CreatedAtUtc = DateTime.UtcNow
                };
                await _profileService.UpdateAsync(profile);
            }
            await LoadProfilesAsync();
        }
        catch { }
    }

    private async Task DeleteProfileAsync()
    {
        if (_selectedProfile == null) return;
        try
        {
            await _profileService.DeleteAsync(_selectedProfile.Id);
            SelectedProfile = null;
            await LoadProfilesAsync();
        }
        catch { }
    }
}
