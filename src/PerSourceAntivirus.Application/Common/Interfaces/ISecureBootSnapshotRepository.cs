using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISecureBootSnapshotRepository
{
    Task AddAsync(SecureBootStatusSnapshot snapshot, CancellationToken ct = default);
    Task<SecureBootStatusSnapshot?> GetLatestAsync(CancellationToken ct = default);
    Task<IReadOnlyList<SecureBootStatusSnapshot>> GetAllAsync(CancellationToken ct = default);
}
