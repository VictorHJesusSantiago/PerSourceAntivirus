namespace PerSourceAntivirus.Application.Common.Interfaces;

public record SelfIntegrityReport(
    bool IsIntact,
    IReadOnlyList<string> TamperedFiles,
    IReadOnlyList<string> MissingFiles,
    DateTime CheckedAtUtc
);

public interface ISelfIntegrityService
{
    Task<SelfIntegrityReport> VerifyAsync(CancellationToken ct = default);
    Task<bool> SaveBaselineAsync(CancellationToken ct = default);
}
