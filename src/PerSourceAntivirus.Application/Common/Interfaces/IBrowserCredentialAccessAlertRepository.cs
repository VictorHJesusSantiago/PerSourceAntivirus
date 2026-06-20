using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IBrowserCredentialAccessAlertRepository
{
    Task AddAsync(BrowserCredentialAccessAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<BrowserCredentialAccessAlert>> GetAllAsync(CancellationToken ct = default);
}
