namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IYaraRulesUpdater
{
    Task<YaraRulesUpdateResult> UpdateAsync(string? sourceUrl = null, CancellationToken cancellationToken = default);
}

public record YaraRulesUpdateResult(int FilesDownloaded, string Source, bool Success, string? ErrorMessage = null);
