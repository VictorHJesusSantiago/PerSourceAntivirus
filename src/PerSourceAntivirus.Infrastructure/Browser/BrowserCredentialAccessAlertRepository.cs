using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Browser;

public sealed class BrowserCredentialAccessAlertRepository(AppDbContext db) : IBrowserCredentialAccessAlertRepository
{
    public async Task AddAsync(BrowserCredentialAccessAlert alert, CancellationToken ct = default)
    {
        db.Set<BrowserCredentialAccessAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<BrowserCredentialAccessAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<BrowserCredentialAccessAlert>()
            .OrderByDescending(a => a.DetectedAtUtc)
            .ToListAsync(ct);
}
