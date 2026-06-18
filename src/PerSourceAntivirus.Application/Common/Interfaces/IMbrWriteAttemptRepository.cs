using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMbrWriteAttemptRepository
{
    Task AddAsync(MbrWriteAttemptAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<MbrWriteAttemptAlert>> GetAllAsync(CancellationToken ct = default);
}
