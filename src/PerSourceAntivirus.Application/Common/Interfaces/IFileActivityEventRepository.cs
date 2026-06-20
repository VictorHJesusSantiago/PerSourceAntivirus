using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IFileActivityEventRepository
{
    Task AddAsync(FileActivityEvent evt, CancellationToken ct = default);
    Task<IReadOnlyList<FileActivityEvent>> GetByProcessIdAsync(int pid, CancellationToken ct = default);
    Task<IReadOnlyList<FileActivityEvent>> GetByFilePathAsync(string path, CancellationToken ct = default);
    Task<IReadOnlyList<FileActivityEvent>> GetRecentAsync(int count, CancellationToken ct = default);
}
