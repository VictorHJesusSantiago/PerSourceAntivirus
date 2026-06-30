using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Kernel;

[SupportedOSPlatform("windows")]
public sealed class SafeFolderService : ISafeFolderService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly List<string> _protectedFolders = [];
    private readonly List<string> _whitelistedProcesses = [];
    private readonly Lock _lock = new();
    private volatile bool _running;

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint FilterConnectCommunicationPort(
        string portName,
        uint options,
        IntPtr context,
        uint sizeOfContext,
        IntPtr securityAttributes,
        out IntPtr port);

    [DllImport("fltlib.dll", SetLastError = true)]
    private static extern uint FilterSendMessage(
        IntPtr port,
        IntPtr inBuffer,
        uint inBufferSize,
        IntPtr outBuffer,
        uint outBufferSize,
        out uint bytesReturned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private const string SafeFolderPortName = @"\PSAVSafeFolderPort";

    public event EventHandler<SafeFolderViolationAlertEventArgs>? ViolationDetected;

    // Per-write scope: AppDbContext is not thread-safe; violations are raised from minifilter callback threads.
    private async Task PersistAsync(SafeFolderViolationAlert alert)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<ISafeFolderViolationRepository>();
            await repository.AddAsync(alert).ConfigureAwait(false);
        }
        catch { }
    }

    public SafeFolderService(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;

        // Default protected folders
        var docs    = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var pics    = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
        var vids    = Environment.GetFolderPath(Environment.SpecialFolder.MyVideos);

        foreach (var folder in new[] { docs, desktop, pics, vids })
            if (!string.IsNullOrEmpty(folder))
                _protectedFolders.Add(folder);

        // Default whitelist: AV itself
        _whitelistedProcesses.Add("PerSourceAntivirus.Cli");
        _whitelistedProcesses.Add("PerSourceAntivirus.Gui");
    }

    public IReadOnlyList<string> GetProtectedFolders()  { lock (_lock) return [.. _protectedFolders]; }
    public IReadOnlyList<string> GetWhitelistedProcesses() { lock (_lock) return [.. _whitelistedProcesses]; }

    public void AddProtectedFolder(string folderPath)
    {
        lock (_lock)
            if (!_protectedFolders.Contains(folderPath, StringComparer.OrdinalIgnoreCase))
                _protectedFolders.Add(folderPath);
    }

    public void RemoveProtectedFolder(string folderPath)
    {
        lock (_lock)
            _protectedFolders.RemoveAll(f => string.Equals(f, folderPath, StringComparison.OrdinalIgnoreCase));
    }

    public void AddWhitelistedProcess(string processName)
    {
        lock (_lock)
            if (!_whitelistedProcesses.Contains(processName, StringComparer.OrdinalIgnoreCase))
                _whitelistedProcesses.Add(processName);
    }

    public void RemoveWhitelistedProcess(string processName)
    {
        lock (_lock)
            _whitelistedProcesses.RemoveAll(p => string.Equals(p, processName, StringComparison.OrdinalIgnoreCase));
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        // Try to connect to the kernel driver port and sync config
        await TrySyncWithDriverAsync(ct);

        // Monitor via filesystem watcher as userspace fallback
        var watchers = new List<FileSystemWatcher>();
        try
        {
            List<string> folders;
            lock (_lock) folders = [.. _protectedFolders];

            foreach (var folder in folders.Where(Directory.Exists))
            {
                var watcher = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = true,
                    EnableRaisingEvents   = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite
                };
                watcher.Changed += (s, e) => OnFsEvent(e.FullPath, "Write");
                watcher.Created += (s, e) => OnFsEvent(e.FullPath, "Write");
                watcher.Deleted += (s, e) => OnFsEvent(e.FullPath, "Delete");
                watcher.Renamed += (s, e) => OnFsEvent(e.FullPath, "Rename");
                watchers.Add(watcher);
            }

            while (_running && !ct.IsCancellationRequested)
                await Task.Delay(1000, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        finally
        {
            foreach (var w in watchers)
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            _running = false;
        }
    }

    public void StopMonitoring() => _running = false;

    private void OnFsEvent(string path, string operation)
    {
        // Check if triggered by a non-whitelisted process
        // (userspace can't reliably get the calling process for FS events — just record it)
        var alert = new SafeFolderViolationAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = "Unknown",
            ProcessId   = 0,
            ProtectedPath = path,
            AttemptedOperation = operation,
            WasBlocked  = false, // userspace watcher is detect-only; kernel driver does actual blocking
            Severity    = 6,
            DetectedAtUtc = DateTime.UtcNow
        };

        _ = PersistAsync(alert);
        ViolationDetected?.Invoke(this, new SafeFolderViolationAlertEventArgs(alert));
    }

    private async Task TrySyncWithDriverAsync(CancellationToken ct)
    {
        // Attempt to connect to \PSAVSafeFolderPort and send folder/process config
        try
        {
            var hr = FilterConnectCommunicationPort(SafeFolderPortName, 0,
                IntPtr.Zero, 0, IntPtr.Zero, out var port);
            if (hr != 0 || port == IntPtr.Zero) return;

            try
            {
                List<string> folders, processes;
                lock (_lock)
                {
                    folders   = [.. _protectedFolders];
                    processes = [.. _whitelistedProcesses];
                }

                foreach (var folder in folders)
                    await SendDriverCommandAsync(port, 1, folder, ct); // Cmd 1 = AddFolder

                foreach (var proc in processes)
                    await SendDriverCommandAsync(port, 3, proc, ct);   // Cmd 3 = AddProcess
            }
            finally
            {
                CloseHandle(port);
            }
        }
        catch { }
    }

    private static unsafe Task SendDriverCommandAsync(IntPtr port, uint command, string path, CancellationToken ct)
    {
        // Kernel's PSAV_SF_PAYLOAD: ULONG Command (4) + WCHAR Path[260] (520) = 524 bytes total.
        // FilterSendMessage passes the raw buffer directly to the kernel's MessageNotify — no header.
        const int MsgSize = 4 + 520;
        var buf = new byte[MsgSize];
        BitConverter.TryWriteBytes(buf.AsSpan(0, 4), command);
        var pathBytes = System.Text.Encoding.Unicode.GetBytes(path);
        var copyLen = Math.Min(pathBytes.Length, 520);
        pathBytes.AsSpan(0, copyLen).CopyTo(buf.AsSpan(4));

        fixed (byte* pBuf = buf)
        {
            FilterSendMessage(port, (IntPtr)pBuf, MsgSize, IntPtr.Zero, 0, out _);
        }
        return Task.CompletedTask;
    }
}
