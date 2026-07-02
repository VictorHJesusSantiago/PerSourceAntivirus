namespace PerSourceAntivirus.Application.Common.Interfaces;

// Tamper-evident audit trail: each entry's hash covers the previous entry's hash plus its own
// content (a simple hash chain / "blockchain of one"), so any edit or deletion of a past entry
// is detectable by re-walking the chain and recomputing hashes.
public interface IAuditLogChainService
{
    Task<string> AppendAsync(string eventDescription, CancellationToken ct = default);
    Task<AuditLogChainVerificationResult> VerifyChainAsync(CancellationToken ct = default);
}

public record AuditLogChainVerificationResult(bool IsIntact, long TotalEntries, long? FirstBrokenSequence);
