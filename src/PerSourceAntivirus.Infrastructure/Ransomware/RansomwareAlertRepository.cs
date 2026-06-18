using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Ransomware;

public class RansomwareAlertRepository(AppDbContext db) : IRansomwareAlertRepository
{
    public async Task AddAsync(RansomwareAlert alert, CancellationToken ct = default)
    {
        db.RansomwareAlerts.Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<RansomwareAlert>> GetAllAsync(bool onlyCritical = false, CancellationToken ct = default)
    {
        var query = db.RansomwareAlerts.AsQueryable();
        if (onlyCritical)
            query = query.Where(a => a.Severity == RansomwareSeverity.Critical);
        return await query.OrderByDescending(a => a.DetectedAtUtc).ToListAsync(ct);
    }
}
