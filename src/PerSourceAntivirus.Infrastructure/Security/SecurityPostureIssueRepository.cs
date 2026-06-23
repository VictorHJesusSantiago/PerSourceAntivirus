using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class SecurityPostureIssueRepository(AppDbContext db) : ISecurityPostureIssueRepository
{
    public async Task AddRangeAsync(IEnumerable<SecurityPostureIssue> items, CancellationToken ct = default)
    {
        db.Set<SecurityPostureIssue>().AddRange(items);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<SecurityPostureIssue>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<SecurityPostureIssue>().OrderByDescending(x => x.CheckedAtUtc).ToListAsync(ct);
}
