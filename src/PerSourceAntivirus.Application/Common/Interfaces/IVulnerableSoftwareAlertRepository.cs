using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IVulnerableSoftwareAlertRepository
{
    Task AddAsync(VulnerableSoftwareAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<VulnerableSoftwareAlert>> GetAllAsync(CancellationToken ct = default);
}
