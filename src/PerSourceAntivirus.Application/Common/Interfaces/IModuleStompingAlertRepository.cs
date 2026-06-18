using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IModuleStompingAlertRepository
{
    Task AddAsync(ModuleStompingAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<ModuleStompingAlert>> GetAllAsync(CancellationToken ct = default);
}
