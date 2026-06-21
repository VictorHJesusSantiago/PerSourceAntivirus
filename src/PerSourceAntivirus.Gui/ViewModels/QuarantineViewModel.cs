using System.Collections.ObjectModel;
using System.Windows;
using MediatR;
using PerSourceAntivirus.Application.Scans.Commands.RestoreFile;
using PerSourceAntivirus.Application.Scans.Queries.GetScannedFiles;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Gui.ViewModels;

public class QuarantineViewModel : ViewModelBase
{
    private readonly IMediator _mediator;

    public ObservableCollection<QuarantineItem> Items { get; } = [];

    private QuarantineItem? _selected;
    public QuarantineItem? SelectedItem { get => _selected; set => Set(ref _selected, value); }

    public QuarantineViewModel(IMediator mediator)
    {
        _mediator = mediator;
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var files = await _mediator.Send(new GetScannedFilesQuery());
            Items.Clear();
            foreach (var f in files.Where(f => f.IsQuarantined))
                Items.Add(new QuarantineItem(f.Id, f.FileName, f.FilePath, f.QuarantinedAtUtc ?? DateTime.MinValue, f.Sha256Hash));
        }
        catch { /* non-fatal */ }
    }

    public async Task RestoreSelectedAsync()
    {
        if (SelectedItem is null) return;
        try
        {
            await _mediator.Send(new RestoreFileCommand(SelectedItem.Id));
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Restore failed: {ex.Message}", "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }
}

public record QuarantineItem(Guid Id, string FileName, string OriginalPath, DateTime QuarantinedAt, string Hash);
