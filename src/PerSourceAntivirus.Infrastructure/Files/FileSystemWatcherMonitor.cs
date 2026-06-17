using System.Runtime.CompilerServices;
using System.Threading.Channels;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Files;

public class FileSystemWatcherMonitor : IFileSystemMonitor
{
    public async IAsyncEnumerable<string> WatchAsync(
        string path,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(path))
        {
            yield break;
        }

        var channel = Channel.CreateUnbounded<string>();

        using var watcher = new FileSystemWatcher(path)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
            EnableRaisingEvents = false
        };

        void OnCreated(object sender, FileSystemEventArgs e)
        {
            if (File.Exists(e.FullPath))
            {
                channel.Writer.TryWrite(e.FullPath);
            }
        }

        void OnChanged(object sender, FileSystemEventArgs e)
        {
            if (File.Exists(e.FullPath))
            {
                channel.Writer.TryWrite(e.FullPath);
            }
        }

        watcher.Created += OnCreated;
        watcher.Changed += OnChanged;
        watcher.EnableRaisingEvents = true;

        cancellationToken.Register(() => channel.Writer.TryComplete());

        try
        {
            await foreach (var filePath in channel.Reader.ReadAllAsync(cancellationToken))
            {
                yield return filePath;
            }
        }
        finally
        {
            watcher.EnableRaisingEvents = false;
            watcher.Created -= OnCreated;
            watcher.Changed -= OnChanged;
        }
    }
}
