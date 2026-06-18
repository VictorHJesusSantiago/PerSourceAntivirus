using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDgaAlertRepository
{
    Task AddAsync(DgaAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<DgaAlert>> GetAllAsync(CancellationToken ct = default);
}
