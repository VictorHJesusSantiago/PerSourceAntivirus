namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHashReputationService
{
    Task<HashReputationData?> CheckAsync(string sha256, CancellationToken cancellationToken = default);
}

public record HashReputationData(
    int PositiveDetections,
    int TotalEngines,
    bool IsMalicious,
    string Source,
    string? ReportUrl);
