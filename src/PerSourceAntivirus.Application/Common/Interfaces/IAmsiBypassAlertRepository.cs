using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAmsiBypassAlertRepository
{
    Task AddAsync(AmsiBypassAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<AmsiBypassAlert>> GetAllAsync(CancellationToken ct = default);
}
