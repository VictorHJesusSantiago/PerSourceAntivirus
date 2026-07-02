using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISampleSubmissionRepository
{
    Task AddAsync(SampleSubmissionRecord record, CancellationToken ct = default);
    Task<IReadOnlyList<SampleSubmissionRecord>> GetAllAsync(CancellationToken ct = default);
}
