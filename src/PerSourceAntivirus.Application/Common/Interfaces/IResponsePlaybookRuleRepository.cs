using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IResponsePlaybookRuleRepository
{
    Task AddAsync(ResponsePlaybookRule rule, CancellationToken ct = default);
    Task<IReadOnlyList<ResponsePlaybookRule>> GetEnabledAsync(CancellationToken ct = default);
    Task<IReadOnlyList<ResponsePlaybookRule>> GetAllAsync(CancellationToken ct = default);
}
