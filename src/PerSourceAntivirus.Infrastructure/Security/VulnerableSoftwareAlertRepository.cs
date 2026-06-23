using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class VulnerableSoftwareAlertRepository(AppDbContext db) : IVulnerableSoftwareAlertRepository
{
    public async Task AddAsync(VulnerableSoftwareAlert alert, CancellationToken ct = default)
    {
        db.Set<VulnerableSoftwareAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<VulnerableSoftwareAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<VulnerableSoftwareAlert>().OrderByDescending(x => x.DetectedAtUtc).ToListAsync(ct);
}
