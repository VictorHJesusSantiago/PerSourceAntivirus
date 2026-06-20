using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPuaAlertRepository
{
    Task AddAsync(PuaAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<PuaAlert>> GetAllAsync(CancellationToken ct = default);
}
