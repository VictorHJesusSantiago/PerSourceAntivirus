using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IKernelPatchGuardAlertRepository
{
    Task AddAsync(KernelPatchGuardAlert alert, CancellationToken ct);
    Task<IReadOnlyList<KernelPatchGuardAlert>> GetAllAsync(CancellationToken ct);
}
