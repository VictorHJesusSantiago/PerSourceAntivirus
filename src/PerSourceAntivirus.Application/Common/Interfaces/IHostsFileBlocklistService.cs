namespace PerSourceAntivirus.Application.Common.Interfaces;

// Writes the domain blocklist into the Windows hosts file (0.0.0.0 sinkhole entries) as a
// lightweight, proxy-free complement to IDnsSinkhole. Managed entries live inside a
// clearly-delimited block so the rest of the hosts file is left untouched.
public interface IHostsFileBlocklistService
{
    Task<int> SyncAsync(CancellationToken ct = default);
    Task RemoveManagedEntriesAsync(CancellationToken ct = default);
}
