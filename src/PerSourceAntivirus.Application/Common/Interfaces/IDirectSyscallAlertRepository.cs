using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDirectSyscallAlertRepository
{
    Task AddAsync(DirectSyscallAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<DirectSyscallAlert>> GetAllAsync(CancellationToken ct = default);
}
