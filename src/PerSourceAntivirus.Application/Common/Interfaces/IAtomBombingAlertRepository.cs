using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAtomBombingAlertRepository
{
    Task AddAsync(AtomBombingAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<AtomBombingAlert>> GetAllAsync(CancellationToken ct = default);
}
