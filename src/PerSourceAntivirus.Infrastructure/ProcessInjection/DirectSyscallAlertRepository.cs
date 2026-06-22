using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

public sealed class DirectSyscallAlertRepository(AppDbContext db) : IDirectSyscallAlertRepository
{
    public async Task AddAsync(DirectSyscallAlert alert, CancellationToken ct = default)
    {
        db.Set<DirectSyscallAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<DirectSyscallAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<DirectSyscallAlert>().ToListAsync(ct);
}
