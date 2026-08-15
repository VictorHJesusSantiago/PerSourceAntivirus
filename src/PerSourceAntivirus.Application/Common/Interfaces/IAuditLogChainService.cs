namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAuditLogChainService
{
    Task<string> AppendAsync(string eventDescription, CancellationToken ct = default);
    Task<AuditLogChainVerificationResult> VerifyChainAsync(CancellationToken ct = default);
}

public record AuditLogChainVerificationResult(bool IsIntact, long TotalEntries, long? FirstBrokenSequence);
