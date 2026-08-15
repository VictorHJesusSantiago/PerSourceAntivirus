namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHostsFileBlocklistService
{
    Task<int> SyncAsync(CancellationToken ct = default);
    Task RemoveManagedEntriesAsync(CancellationToken ct = default);
}
