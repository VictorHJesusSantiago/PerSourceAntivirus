using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class ServiceAuditFindingRepository(AppDbContext db) : IServiceAuditFindingRepository
{
    public async Task AddAsync(ServiceAuditFinding finding, CancellationToken ct = default)
    {
        db.Set<ServiceAuditFinding>().Add(finding);
        await db.SaveChangesAsync(ct);
    }

    public async Task AddRangeAsync(IEnumerable<ServiceAuditFinding> items, CancellationToken ct = default)
    {
        db.Set<ServiceAuditFinding>().AddRange(items);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ServiceAuditFinding>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ServiceAuditFinding>().OrderByDescending(x => x.AuditedAtUtc).ToListAsync(ct);
}
