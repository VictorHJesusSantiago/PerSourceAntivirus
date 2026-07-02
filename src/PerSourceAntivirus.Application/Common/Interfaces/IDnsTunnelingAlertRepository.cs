using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDnsTunnelingAlertRepository
{
    Task AddAsync(DnsTunnelingAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<DnsTunnelingAlert>> GetAllAsync(CancellationToken ct = default);
}
