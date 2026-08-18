using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Files;

namespace PerSourceAntivirus.Infrastructure.Tests.Files;

public class FileSystemWatcherMonitorTests
{
    [Fact]
    public async Task WatchAsync_YieldsCreatedFilePath()
    {
        var watchDir = Directory.CreateTempSubdirectory().FullName;
        var monitor = new FileSystemWatcherMonitor();
        var detected = new List<string>();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var fileCreated = new TaskCompletionSource();

        var watchTask = Task.Run(async () =>
        {
            await foreach (var path in monitor.WatchAsync(watchDir, cts.Token))
            {
                detected.Add(path);
                fileCreated.TrySetResult();
                cts.Cancel();
            }
        });

        await Task.Delay(1000);

        var newFile = Path.Combine(watchDir, "new.txt");
        await File.WriteAllTextAsync(newFile, "test");

        await Task.WhenAny(fileCreated.Task, Task.Delay(8000));
        cts.Cancel();

        try
        {
            await watchTask;
        }
        catch (OperationCanceledException) { }
        finally
        {
            try { Directory.Delete(watchDir, recursive: true); } catch { }
        }

        detected.Should().Contain(newFile);
        detected.Should().AllSatisfy(p => p.Should().Be(newFile));
    }

    [Fact]
    public async Task WatchAsync_CompletesImmediately_WhenDirectoryDoesNotExist()
    {
        var monitor = new FileSystemWatcherMonitor();
        var nonExistent = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var paths = new List<string>();

        await foreach (var path in monitor.WatchAsync(nonExistent))
        {
            paths.Add(path);
        }

        paths.Should().BeEmpty();
    }
}
