using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ILlmnrPoisoningAlertRepository
{
    Task AddAsync(LlmnrPoisoningAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<LlmnrPoisoningAlert>> GetAllAsync(CancellationToken ct = default);
}
