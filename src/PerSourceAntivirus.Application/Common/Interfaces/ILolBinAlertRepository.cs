using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ILolBinAlertRepository
{
    Task AddAsync(LolBinAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<LolBinAlert>> GetAllAsync(CancellationToken ct = default);
}
