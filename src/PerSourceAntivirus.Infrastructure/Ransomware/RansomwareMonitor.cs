using System.Collections.Concurrent;
using System.Management;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Infrastructure.Ransomware;

public class RansomwareMonitor : IRansomwareMonitor
{
    private static readonly string[] SuspiciousExtensions =
    [
        ".locked", ".encrypted", ".wncry", ".cerber", ".locky",
        ".cry", ".enc", ".crypted", ".aaa", ".abc", ".xyz",
        ".zzz", ".micro", ".ttt", ".crypt", ".crypz", ".pays",
        ".deadbolt", ".crypt14", ".clop"
    ];

    public async IAsyncEnumerable<RansomwareAlert> WatchAsync(
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        var channel = Channel.CreateUnbounded<RansomwareAlert>(
            new UnboundedChannelOptions { SingleWriter = false, SingleReader = true });

        var watchDirs = BuildWatchDirectories();
        var honeypotPaths = LoadHoneypotPaths(watchDirs);
        var recentChanges = new ConcurrentQueue<DateTime>();
        var watchers = new List<FileSystemWatcher>();

        foreach (var dir in watchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            var watcher = new FileSystemWatcher(dir)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                IncludeSubdirectories = false,
                EnableRaisingEvents = true
            };
            watcher.Changed += (_, e) => HandleChange(e.FullPath, e.Name ?? string.Empty,
                e.ChangeType, honeypotPaths, recentChanges, channel.Writer);
            watcher.Created += (_, e) => HandleChange(e.FullPath, e.Name ?? string.Empty,
                e.ChangeType, honeypotPaths, recentChanges, channel.Writer);
            watcher.Renamed += (_, e) => HandleRename(e.FullPath, e.OldName ?? string.Empty,
                e.Name ?? string.Empty, honeypotPaths, recentChanges, channel.Writer);
            watchers.Add(watcher);
        }

        ManagementEventWatcher? vssWatcher = null;
        try
        {
            var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            vssWatcher = new ManagementEventWatcher(query);
            vssWatcher.EventArrived += (_, args) =>
            {
                if (ct.IsCancellationRequested) return;
                var name = (args.NewEvent["ProcessName"]?.ToString() ?? string.Empty).ToLowerInvariant();
                if (name is "vssadmin.exe" or "wmic.exe" or "powershell.exe")
                {
                    channel.Writer.TryWrite(new RansomwareAlert
                    {
                        EventType = RansomwareEventType.VssDeletionAttempt,
                        Severity = RansomwareSeverity.High,
                        FilePath = string.Empty,
                        ProcessName = args.NewEvent["ProcessName"]?.ToString(),
                        Detail = $"Potentially suspicious process started: '{args.NewEvent["ProcessName"]}' — may attempt VSS/shadow copy deletion."
                    });
                }
            };
            vssWatcher.Start();
        }
        catch { /* WMI unavailable or admin required — non-fatal */ }

        ct.Register(() =>
        {
            foreach (var w in watchers) { w.EnableRaisingEvents = false; w.Dispose(); }
            try { vssWatcher?.Stop(); vssWatcher?.Dispose(); } catch { }
            channel.Writer.TryComplete();
        });

        await foreach (var alert in channel.Reader.ReadAllAsync(ct))
            yield return alert;
    }

    private static HashSet<string> BuildWatchDirectories() =>
    [
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
    ];

    private static HashSet<string> LoadHoneypotPaths(HashSet<string> dirs)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var f in Directory.GetFiles(dir, "_psav_decoy_*"))
                paths.Add(f);
        }
        return paths;
    }

    private static void HandleChange(
        string fullPath,
        string name,
        WatcherChangeTypes changeType,
        HashSet<string> honeypotPaths,
        ConcurrentQueue<DateTime> recentChanges,
        ChannelWriter<RansomwareAlert> writer)
    {
        if (honeypotPaths.Contains(fullPath))
        {
            writer.TryWrite(new RansomwareAlert
            {
                EventType = RansomwareEventType.HoneypotTouched,
                Severity = RansomwareSeverity.Critical,
                FilePath = fullPath,
                Detail = $"Honeypot decoy file '{name}' was accessed or modified — high-confidence ransomware activity."
            });
            return;
        }

        var now = DateTime.UtcNow;
        recentChanges.Enqueue(now);
        while (recentChanges.TryPeek(out var oldest) && (now - oldest).TotalSeconds > 30)
            recentChanges.TryDequeue(out _);

        if (recentChanges.Count >= 10)
        {
            writer.TryWrite(new RansomwareAlert
            {
                EventType = RansomwareEventType.MassEncryptionDetected,
                Severity = RansomwareSeverity.High,
                FilePath = fullPath,
                Detail = $"Mass file modification: {recentChanges.Count} files changed in ≤30 seconds — possible mass encryption."
            });
        }

        var ext = Path.GetExtension(fullPath).ToLowerInvariant();
        if (Array.IndexOf(SuspiciousExtensions, ext) >= 0)
        {
            writer.TryWrite(new RansomwareAlert
            {
                EventType = RansomwareEventType.SuspiciousRename,
                Severity = RansomwareSeverity.High,
                FilePath = fullPath,
                Detail = $"File has known ransomware extension: {ext}"
            });
        }

        if (changeType == WatcherChangeTypes.Changed && File.Exists(fullPath))
        {
            try
            {
                var bytes = ReadFirstBytes(fullPath, 65536);
                if (bytes.Length > 512)
                {
                    var entropy = ComputeEntropy(bytes);
                    if (entropy >= 7.2)
                    {
                        writer.TryWrite(new RansomwareAlert
                        {
                            EventType = RansomwareEventType.MassEncryptionDetected,
                            Severity = RansomwareSeverity.Warning,
                            FilePath = fullPath,
                            Detail = $"High-entropy file write (entropy={entropy:F2}): possible in-progress encryption."
                        });
                    }
                }
            }
            catch { /* file locked or deleted — skip */ }
        }
    }

    private static void HandleRename(
        string fullPath,
        string oldName,
        string newName,
        HashSet<string> honeypotPaths,
        ConcurrentQueue<DateTime> recentChanges,
        ChannelWriter<RansomwareAlert> writer)
    {
        HandleChange(fullPath, newName, WatcherChangeTypes.Renamed, honeypotPaths, recentChanges, writer);

        var ext = Path.GetExtension(newName).ToLowerInvariant();
        if (Array.IndexOf(SuspiciousExtensions, ext) >= 0)
        {
            writer.TryWrite(new RansomwareAlert
            {
                EventType = RansomwareEventType.SuspiciousRename,
                Severity = RansomwareSeverity.High,
                FilePath = fullPath,
                Detail = $"File renamed from '{oldName}' → '{newName}' with ransomware extension: {ext}"
            });
        }
    }

    private static byte[] ReadFirstBytes(string path, int count)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var len = (int)Math.Min(count, fs.Length);
        var buf = new byte[len];
        _ = fs.Read(buf, 0, len);
        return buf;
    }

    private static double ComputeEntropy(byte[] data)
    {
        var freq = new int[256];
        foreach (var b in data) freq[b]++;
        var entropy = 0.0;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            var p = (double)f / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
