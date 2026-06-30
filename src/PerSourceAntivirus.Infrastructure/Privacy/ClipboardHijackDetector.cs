using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Privacy;

[SupportedOSPlatform("windows")]
public sealed class ClipboardHijackDetector : IClipboardHijackDetector
{
    private readonly IServiceScopeFactory _scopeFactory;
    private volatile bool _running;
    private string _lastContent = string.Empty;

    private static readonly (Regex Pattern, string AddressType)[] CryptoPatterns =
    [
        (new Regex(@"\b(1|3|bc1)[A-HJ-NP-Za-km-z1-9]{25,62}\b", RegexOptions.Compiled), "Bitcoin"),
        (new Regex(@"\b0x[0-9a-fA-F]{40}\b", RegexOptions.Compiled), "Ethereum"),
        (new Regex(@"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", RegexOptions.Compiled), "Monero"),
    ];

    [DllImport("user32.dll")]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll")]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll")]
    private static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern bool GlobalUnlock(IntPtr hMem);

    private const uint CF_UNICODETEXT = 13;

    public event EventHandler<ClipboardHijackAlertEventArgs>? AlertDetected;

    public ClipboardHijackDetector(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    // Per-write scope: AppDbContext is not thread-safe; alerts are raised from monitor threads.
    private async Task PersistAsync(ClipboardHijackAlert alert)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IClipboardHijackAlertRepository>();
            await repository.AddAsync(alert).ConfigureAwait(false);
        }
        catch { }
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        try
        {
            while (!ct.IsCancellationRequested && _running)
            {
                try
                {
                    var content = ReadClipboardText();
                    if (!string.IsNullOrEmpty(content) && content != _lastContent)
                    {
                        _lastContent = content;
                        CheckForCryptoAddress(content);
                    }
                }
                catch { }
                await Task.Delay(TimeSpan.FromMilliseconds(500), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private static string ReadClipboardText()
    {
        if (!OpenClipboard(IntPtr.Zero))
            return string.Empty;

        try
        {
            var hData = GetClipboardData(CF_UNICODETEXT);
            if (hData == IntPtr.Zero)
                return string.Empty;

            var locked = GlobalLock(hData);
            if (locked == IntPtr.Zero)
                return string.Empty;

            try
            {
                return Marshal.PtrToStringUni(locked) ?? string.Empty;
            }
            finally
            {
                GlobalUnlock(hData);
            }
        }
        finally
        {
            CloseClipboard();
        }
    }

    private void CheckForCryptoAddress(string content)
    {
        foreach (var (pattern, addressType) in CryptoPatterns)
        {
            var match = pattern.Match(content);
            if (!match.Success)
                continue;

            var alert = new ClipboardHijackAlert
            {
                Id = Guid.NewGuid(),
                ProcessName = "Unknown",
                ProcessId = 0,
                OriginalContent = content.Length > 100 ? content[..100] : content,
                SuspectedWalletAddress = match.Value,
                AddressType = addressType,
                WasBlocked = false,
                Severity = 8,
                DetectedAtUtc = DateTime.UtcNow
            };

            _ = PersistAsync(alert);
            AlertDetected?.Invoke(this, new ClipboardHijackAlertEventArgs(alert));
            break;
        }
    }
}
