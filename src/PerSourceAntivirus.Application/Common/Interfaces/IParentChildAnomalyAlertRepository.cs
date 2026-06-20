using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IParentChildAnomalyAlertRepository
{
    Task AddAsync(ParentChildAnomalyAlert alert, CancellationToken ct);
    Task<IReadOnlyList<ParentChildAnomalyAlert>> GetAllAsync(CancellationToken ct);
}
