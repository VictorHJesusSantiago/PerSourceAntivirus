using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class KernelPatchGuardAlertRepository(AppDbContext db) : IKernelPatchGuardAlertRepository
{
    public async Task AddAsync(KernelPatchGuardAlert alert, CancellationToken ct)
    {
        db.Set<KernelPatchGuardAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<KernelPatchGuardAlert>> GetAllAsync(CancellationToken ct)
        => await db.Set<KernelPatchGuardAlert>().OrderByDescending(a => a.DetectedAtUtc).ToListAsync(ct);
}
