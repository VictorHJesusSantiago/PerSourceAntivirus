using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IWmiPersistenceScanner
{
    Task<IReadOnlyList<WmiPersistenceAlert>> ScanAsync(CancellationToken ct = default);
}

public interface IWmiPersistenceAlertRepository
{
    Task AddRangeAsync(IEnumerable<WmiPersistenceAlert> alerts, CancellationToken ct = default);
    Task<IReadOnlyList<WmiPersistenceAlert>> GetAllAsync(CancellationToken ct = default);
}
