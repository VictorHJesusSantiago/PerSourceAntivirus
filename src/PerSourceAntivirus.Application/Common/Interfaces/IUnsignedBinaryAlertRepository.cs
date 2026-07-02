using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IUnsignedBinaryAlertRepository
{
    Task AddAsync(UnsignedBinaryAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<UnsignedBinaryAlert>> GetAllAsync(CancellationToken ct = default);
}
