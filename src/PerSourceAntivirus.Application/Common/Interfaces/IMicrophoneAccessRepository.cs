using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMicrophoneAccessRepository
{
    Task AddAsync(MicrophoneAccessEvent accessEvent, CancellationToken ct = default);
    Task<IReadOnlyList<MicrophoneAccessEvent>> GetAllAsync(CancellationToken ct = default);
}
