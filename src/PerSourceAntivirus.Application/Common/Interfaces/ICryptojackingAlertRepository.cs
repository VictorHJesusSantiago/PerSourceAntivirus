using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICryptojackingAlertRepository
{
    Task AddAsync(CryptojackingAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<CryptojackingAlert>> GetAllAsync(CancellationToken ct = default);
}
