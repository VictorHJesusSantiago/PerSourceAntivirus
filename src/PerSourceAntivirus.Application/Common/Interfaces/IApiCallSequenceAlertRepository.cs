using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IApiCallSequenceAlertRepository
{
    Task AddAsync(ApiCallSequenceAlert alert, CancellationToken ct);
    Task<IReadOnlyList<ApiCallSequenceAlert>> GetAllAsync(CancellationToken ct);
}
