using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IQuarantineService
{
    Task<string> QuarantineAsync(ScannedFile file, CancellationToken cancellationToken = default);
    Task RestoreAsync(ScannedFile file, CancellationToken cancellationToken = default);
}
