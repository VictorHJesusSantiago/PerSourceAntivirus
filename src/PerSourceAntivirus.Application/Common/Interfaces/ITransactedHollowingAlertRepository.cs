using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ITransactedHollowingAlertRepository
{
    Task AddAsync(TransactedHollowingAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<TransactedHollowingAlert>> GetAllAsync(CancellationToken ct = default);
}
