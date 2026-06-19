using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IWpadAbuseAlertRepository
{
    Task AddAsync(WpadAbuseAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<WpadAbuseAlert>> GetAllAsync(CancellationToken ct = default);
}
