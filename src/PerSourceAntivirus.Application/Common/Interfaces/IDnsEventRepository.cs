using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDnsEventRepository
{
    Task AddRangeAsync(IEnumerable<DnsQueryEvent> events, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<DnsQueryEvent>> GetAllAsync(bool onlySuspicious = false, CancellationToken cancellationToken = default);
}
