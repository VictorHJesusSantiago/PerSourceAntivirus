using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISupplyChainAlertRepository
{
    Task AddAsync(SupplyChainAlert alert, CancellationToken ct);
    Task<IReadOnlyList<SupplyChainAlert>> GetAllAsync(CancellationToken ct);
}
