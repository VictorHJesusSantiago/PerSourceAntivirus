using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHeapSprayAlertRepository
{
    Task AddAsync(HeapSprayAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<HeapSprayAlert>> GetAllAsync(CancellationToken ct = default);
}
