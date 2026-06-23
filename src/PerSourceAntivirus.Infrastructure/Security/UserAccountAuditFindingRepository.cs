using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class UserAccountAuditFindingRepository(AppDbContext db) : IUserAccountAuditFindingRepository
{
    public async Task AddAsync(UserAccountAuditFinding finding, CancellationToken ct = default)
    {
        db.Set<UserAccountAuditFinding>().Add(finding);
        await db.SaveChangesAsync(ct);
    }

    public async Task AddRangeAsync(IEnumerable<UserAccountAuditFinding> items, CancellationToken ct = default)
    {
        db.Set<UserAccountAuditFinding>().AddRange(items);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<UserAccountAuditFinding>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<UserAccountAuditFinding>().OrderByDescending(x => x.AuditedAtUtc).ToListAsync(ct);
}
