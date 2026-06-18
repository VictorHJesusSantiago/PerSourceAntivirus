using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IFilelessAlertRepository
{
    Task AddAsync(FilelessAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<FilelessAlert>> GetAllAsync(CancellationToken ct = default);
}
