using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Etw;

// Real-time ETW monitor using the kernel provider.
// Detects: DLL injection (load from suspicious path), Run-key persistence, process creation.
// Requires Windows administrator privileges.
public sealed class EtwMonitor : IEtwMonitor
{
    private const string SessionName = "PerSourceAntivirusEtw";

    // Paths that indicate a possibly injected DLL (temp dirs, appdata).
    private static readonly string[] SuspiciousDllPaths =
    [
        Path.GetTempPath(),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        @"\AppData\",
        @"\Temp\",
        @"\tmp\",
    ];

    // NT-format Registry Run key prefixes for both HKLM and HKCU.
    private static readonly string[] RunKeyPrefixes =
    [
        @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"\REGISTRY\USER\",   // followed by SID + \...\Run — checked separately
    ];

    public async IAsyncEnumerable<EtwEventData> WatchAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var channel = Channel.CreateUnbounded<EtwEventData>(
            new UnboundedChannelOptions { SingleReader = true });

        var sessionTask = Task.Run(() =>
        {
            try
            {
                // TraceEventSession requires admin; will throw UnauthorizedAccessException otherwise.
                using var session = new TraceEventSession(SessionName);

                cancellationToken.Register(() =>
                {
                    try { session.Stop(); } catch { /* ignore on shutdown */ }
                });

                session.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.ImageLoad |
                    KernelTraceEventParser.Keywords.Registry |
                    KernelTraceEventParser.Keywords.Process);

                session.Source.Kernel.ImageLoad += data =>
                {
                    var ev = AnalyzeImageLoad(data);
                    channel.Writer.TryWrite(ev);
                };

                session.Source.Kernel.RegistrySetValue += data =>
                {
                    var ev = AnalyzeRegistrySetValue(data);
                    channel.Writer.TryWrite(ev);
                };

                session.Source.Kernel.ProcessStart += data =>
                {
                    var ev = AnalyzeProcessStart(data);
                    channel.Writer.TryWrite(ev);
                };

                // Blocks until session is stopped.
                session.Source.Process();
            }
            catch (Exception ex)
            {
                // Emit an error event and complete so the consumer can exit gracefully.
                channel.Writer.TryWrite(new EtwEventData(
                    DateTime.UtcNow, EtwEventType.Other, 0, "EtwMonitor",
                    $"Session error: {ex.Message}", false, null));
            }
            finally
            {
                channel.Writer.TryComplete();
            }
        }, CancellationToken.None); // Use None so the task body runs even after cancel

        await foreach (var ev in channel.Reader.ReadAllAsync(cancellationToken))
            yield return ev;

        await sessionTask.ConfigureAwait(false);
    }

    private static EtwEventData AnalyzeImageLoad(ImageLoadTraceData data)
    {
        var path    = data.FileName ?? string.Empty;
        var suspect = IsSuspiciousDllPath(path);
        return new EtwEventData(
            DateTime.UtcNow, EtwEventType.DllLoad,
            data.ProcessID, data.ProcessName,
            $"Loaded: {path}",
            suspect,
            suspect ? $"DLL loaded from suspicious path: {path}" : null);
    }

    private static EtwEventData AnalyzeRegistrySetValue(RegistryTraceData data)
    {
        var key     = data.KeyName ?? string.Empty;
        var suspect = IsRunKeyPath(key);
        return new EtwEventData(
            DateTime.UtcNow, EtwEventType.RegistryWrite,
            data.ProcessID, data.ProcessName,
            $"Set: {key}\\{data.ValueName}",
            suspect,
            suspect ? $"Write to auto-run registry key: {key}" : null);
    }

    private static EtwEventData AnalyzeProcessStart(ProcessTraceData data)
    {
        return new EtwEventData(
            DateTime.UtcNow, EtwEventType.ProcessCreate,
            data.ProcessID, data.ProcessName,
            $"Parent PID: {data.ParentID} | Cmd: {data.CommandLine}",
            false, null);
    }

    private static bool IsSuspiciousDllPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        foreach (var prefix in SuspiciousDllPaths)
            if (prefix.Length > 0 &&
                path.Contains(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static bool IsRunKeyPath(string keyName)
    {
        if (string.IsNullOrEmpty(keyName)) return false;
        foreach (var prefix in RunKeyPrefixes)
        {
            if (keyName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                // For HKCU (\REGISTRY\USER\<SID>\...) check if it ends in a Run/RunOnce path.
                if (prefix.EndsWith(@"\REGISTRY\USER\", StringComparison.OrdinalIgnoreCase))
                {
                    return keyName.Contains(@"\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase);
                }
                return true;
            }
        }
        return false;
    }
}
