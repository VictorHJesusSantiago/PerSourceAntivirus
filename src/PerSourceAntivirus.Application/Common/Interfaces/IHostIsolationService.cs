namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHostIsolationService
{
    Task IsolateAsync(string reason, CancellationToken ct = default);
    Task RestoreAsync(CancellationToken ct = default);
    bool IsIsolated { get; }
}
