using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScriptSandboxResultRepository
{
    Task AddAsync(ScriptSandboxResult result, CancellationToken ct = default);
    Task<IReadOnlyList<ScriptSandboxResult>> GetRecentAsync(int count, CancellationToken ct = default);
}
