using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IWebcamAccessRepository
{
    Task AddAsync(WebcamAccessEvent accessEvent, CancellationToken ct = default);
    Task<IReadOnlyList<WebcamAccessEvent>> GetAllAsync(CancellationToken ct = default);
}
