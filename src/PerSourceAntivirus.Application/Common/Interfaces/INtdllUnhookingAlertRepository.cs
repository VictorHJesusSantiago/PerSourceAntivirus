using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INtdllUnhookingAlertRepository
{
    Task AddAsync(NtdllUnhookingAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<NtdllUnhookingAlert>> GetAllAsync(CancellationToken ct = default);
}
