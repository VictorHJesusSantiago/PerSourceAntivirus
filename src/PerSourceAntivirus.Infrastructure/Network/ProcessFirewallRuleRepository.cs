using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class ProcessFirewallRuleRepository(AppDbContext db) : IProcessFirewallRuleRepository
{
    public async Task AddAsync(ProcessFirewallRule rule, CancellationToken ct = default)
    {
        db.Set<ProcessFirewallRule>().Add(rule);
        await db.SaveChangesAsync(ct);
    }

    public async Task RemoveAsync(string processPath, CancellationToken ct = default)
    {
        var existing = await db.Set<ProcessFirewallRule>()
            .Where(r => r.ProcessPath == processPath)
            .ToListAsync(ct);
        db.Set<ProcessFirewallRule>().RemoveRange(existing);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ProcessFirewallRule>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ProcessFirewallRule>().ToListAsync(ct);
}
