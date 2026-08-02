using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class AuditLogChainService(IServiceScopeFactory scopeFactory) : IAuditLogChainService
{
    private const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
    private static readonly SemaphoreSlim AppendLock = new(1, 1);

    public async Task<string> AppendAsync(string eventDescription, CancellationToken ct = default)
    {
        await AppendLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            var last = await db.Set<AuditLogChainEntry>()
                .OrderByDescending(e => e.SequenceNumber)
                .FirstOrDefaultAsync(ct)
                .ConfigureAwait(false);

            var sequenceNumber = (last?.SequenceNumber ?? 0) + 1;
            var previousHash = last?.EntryHash ?? GenesisHash;
            var recordedAt = DateTime.UtcNow;
            var entryHash = ComputeHash(previousHash, sequenceNumber, eventDescription, recordedAt);

            var entry = new AuditLogChainEntry
            {
                Id = Guid.NewGuid(),
                SequenceNumber = sequenceNumber,
                EventDescription = eventDescription,
                PreviousHash = previousHash,
                EntryHash = entryHash,
                RecordedAtUtc = recordedAt
            };

            db.Set<AuditLogChainEntry>().Add(entry);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            return entryHash;
        }
        finally
        {
            AppendLock.Release();
        }
    }

    public async Task<AuditLogChainVerificationResult> VerifyChainAsync(CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var entries = await db.Set<AuditLogChainEntry>()
            .OrderBy(e => e.SequenceNumber)
            .ToListAsync(ct)
            .ConfigureAwait(false);

        var expectedPrevious = GenesisHash;
        foreach (var entry in entries)
        {
            if (entry.PreviousHash != expectedPrevious)
                return new AuditLogChainVerificationResult(false, entries.Count, entry.SequenceNumber);

            var recomputed = ComputeHash(entry.PreviousHash, entry.SequenceNumber, entry.EventDescription, entry.RecordedAtUtc);
            if (recomputed != entry.EntryHash)
                return new AuditLogChainVerificationResult(false, entries.Count, entry.SequenceNumber);

            expectedPrevious = entry.EntryHash;
        }

        return new AuditLogChainVerificationResult(true, entries.Count, null);
    }

    private static string ComputeHash(string previousHash, long sequenceNumber, string eventDescription, DateTime recordedAtUtc)
    {
        var payload = $"{previousHash}|{sequenceNumber}|{eventDescription}|{recordedAtUtc:O}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexStringLower(bytes);
    }
}
