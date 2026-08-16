using Microsoft.Extensions.DependencyInjection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

[SupportedOSPlatform("windows")]
public sealed class AtomBombingDetector : IAtomBombingDetector
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GlobalGetAtomName(ushort nAtom, System.Text.StringBuilder lpBuffer, int nSize);

    public event EventHandler<AtomBombingAlertEventArgs>? AlertDetected;

    private volatile bool _running;
    private readonly HashSet<ushort> _alertedAtoms = new();
    private readonly Microsoft.Extensions.DependencyInjection.IServiceScopeFactory _scopeFactory;

    public AtomBombingDetector(Microsoft.Extensions.DependencyInjection.IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    private async Task PersistAsync(AtomBombingAlert alert, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IAtomBombingAlertRepository>();
            await repository.AddAsync(alert, ct).ConfigureAwait(false);
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
                await Diagnostics.DetectorScanScope.RunAsync(_scopeFactory, nameof(AtomBombingDetector), () => ScanOnceAsync(ct));
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private async Task ScanOnceAsync(CancellationToken ct)
    {
        int iteration = 0;
        for (int i = 0xC000; i < 0xFFFF; i++)
        {
            if (ct.IsCancellationRequested) break;

            ushort atom = (ushort)i;
            var sb = new System.Text.StringBuilder(260);
            uint len = GlobalGetAtomName(atom, sb, 260);

            if (len == 0) continue;

            string content = sb.ToString();
            double entropy = CalculateEntropy(System.Text.Encoding.Unicode.GetBytes(content));

            if (entropy > 4.5 && content.Length > 20 && !_alertedAtoms.Contains(atom))
            {
                _alertedAtoms.Add(atom);

                var alert = new AtomBombingAlert
                {
                    Id = Guid.NewGuid(),
                    SuspiciousAtomContent = content.Length > 100 ? content[..100] : content,
                    AtomId = atom,
                    AtomContentEntropy = entropy,
                    AtomContentLength = content.Length,
                    SuspicionReason = "HighEntropyAtomContent",
                    Severity = entropy > 5.5 ? 8 : 6,
                    DetectedAtUtc = DateTime.UtcNow
                };

                await PersistAsync(alert, ct).ConfigureAwait(false);

                AlertDetected?.Invoke(this, new AtomBombingAlertEventArgs(alert));
            }

            iteration++;
            if (iteration % 1000 == 0)
                await Task.Yield();
        }
    }

    private static double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        var freq = new int[256];
        foreach (var b in data) freq[b]++;
        double entropy = 0;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            double p = (double)f / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
