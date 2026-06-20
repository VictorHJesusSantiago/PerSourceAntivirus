using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IStixFeedImporter
{
    Task<int> ImportFromUrlAsync(string url, string feedName, CancellationToken ct = default);
    Task<IReadOnlyList<StixFeedSource>> GetFeedSourcesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<StixIoc>> GetIocsAsync(Guid? feedId, CancellationToken ct = default);
}
