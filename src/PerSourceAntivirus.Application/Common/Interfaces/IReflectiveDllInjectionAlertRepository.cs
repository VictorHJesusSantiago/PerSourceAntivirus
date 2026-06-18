using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IReflectiveDllInjectionAlertRepository
{
    Task AddAsync(ReflectiveDllInjectionAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<ReflectiveDllInjectionAlert>> GetAllAsync(CancellationToken ct = default);
}
