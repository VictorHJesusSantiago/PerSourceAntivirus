using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Sandbox;

public sealed class ScriptSandboxResultRepository(AppDbContext db) : IScriptSandboxResultRepository
{
    public async Task AddAsync(ScriptSandboxResult result, CancellationToken ct = default)
    {
        db.Set<ScriptSandboxResult>().Add(result);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ScriptSandboxResult>> GetRecentAsync(int count, CancellationToken ct = default)
        => await db.Set<ScriptSandboxResult>()
            .OrderByDescending(r => r.AnalyzedAtUtc)
            .Take(count)
            .ToListAsync(ct);
}
