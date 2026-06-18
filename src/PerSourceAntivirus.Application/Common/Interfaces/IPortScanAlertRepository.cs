using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPortScanAlertRepository
{
    Task AddAsync(PortScanAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<PortScanAlert>> GetAllAsync(CancellationToken ct = default);
}
