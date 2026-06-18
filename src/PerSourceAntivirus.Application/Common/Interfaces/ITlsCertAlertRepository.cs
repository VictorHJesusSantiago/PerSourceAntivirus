using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ITlsCertAlertRepository
{
    Task AddAsync(TlsCertAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<TlsCertAlert>> GetAllAsync(CancellationToken ct = default);
}
