using PerSourceAntivirus.Domain.Entities;
namespace PerSourceAntivirus.Application.Common.Interfaces;
public interface IUefiScanner
{
    Task<IReadOnlyList<UefiFinding>> ScanAsync(CancellationToken ct = default);
}
public interface IUefiFindingRepository
{
    Task AddRangeAsync(IEnumerable<UefiFinding> findings, CancellationToken ct = default);
    Task<IReadOnlyList<UefiFinding>> GetAllAsync(CancellationToken ct = default);
}
