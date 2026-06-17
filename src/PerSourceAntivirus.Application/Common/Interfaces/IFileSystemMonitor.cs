namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IFileSystemMonitor
{
    IAsyncEnumerable<string> WatchAsync(string path, CancellationToken cancellationToken = default);
}
