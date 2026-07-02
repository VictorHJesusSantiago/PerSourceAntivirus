using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDllHijackAlertRepository
{
    Task AddAsync(DllHijackAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<DllHijackAlert>> GetAllAsync(CancellationToken ct = default);
}
