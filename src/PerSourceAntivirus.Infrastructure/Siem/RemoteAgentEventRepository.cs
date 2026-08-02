using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Siem;

public sealed class RemoteAgentEventRepository(AppDbContext db) : IRemoteAgentEventRepository
{
    public async Task AddAsync(RemoteAgentEvent evt, CancellationToken ct = default)
    {
        db.Set<RemoteAgentEvent>().Add(evt);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<RemoteAgentEvent>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<RemoteAgentEvent>().ToListAsync(ct);
}
