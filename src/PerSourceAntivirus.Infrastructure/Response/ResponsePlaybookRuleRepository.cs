using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Response;

public sealed class ResponsePlaybookRuleRepository(AppDbContext db) : IResponsePlaybookRuleRepository
{
    public async Task AddAsync(ResponsePlaybookRule rule, CancellationToken ct = default)
    {
        db.Set<ResponsePlaybookRule>().Add(rule);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ResponsePlaybookRule>> GetEnabledAsync(CancellationToken ct = default)
        => await db.Set<ResponsePlaybookRule>().Where(r => r.IsEnabled).ToListAsync(ct);

    public async Task<IReadOnlyList<ResponsePlaybookRule>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ResponsePlaybookRule>().ToListAsync(ct);
}
