using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Files;

public class FileQuarantineService(string quarantineDirectory) : IQuarantineService
{
    public Task<string> QuarantineAsync(ScannedFile file, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(quarantineDirectory);

        // Append .quarantine to prevent accidental execution of moved files.
        var quarantineFileName = $"{file.Id}_{Path.GetFileName(file.FilePath)}.quarantine";
        var quarantinePath = Path.Combine(quarantineDirectory, quarantineFileName);

        File.Move(file.FilePath, quarantinePath);
        return Task.FromResult(quarantinePath);
    }

    public Task RestoreAsync(ScannedFile file, CancellationToken cancellationToken = default)
    {
        if (file.QuarantinePath is null)
        {
            throw new InvalidOperationException("Quarantine path is not recorded.");
        }

        if (!File.Exists(file.QuarantinePath))
        {
            throw new FileNotFoundException($"Quarantined file not found: {file.QuarantinePath}");
        }

        var restoreDirectory = Path.GetDirectoryName(file.FilePath);
        if (restoreDirectory is not null)
        {
            Directory.CreateDirectory(restoreDirectory);
        }

        File.Move(file.QuarantinePath, file.FilePath, overwrite: false);
        return Task.CompletedTask;
    }
}
