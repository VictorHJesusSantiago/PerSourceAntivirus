using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IStackPivotAlertRepository
{
    Task AddAsync(StackPivotAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<StackPivotAlert>> GetAllAsync(CancellationToken ct = default);
}
