using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Diagnostics;

// Encapsulates the "measure a scan iteration, report success or failure, never let the exception
// escape" pattern (ADR-001) so it isn't hand-rolled ~90 times across the detectors.
//
// Usage inside a detector's polling loop:
//     await DetectorScanScope.RunAsync(_diagnostics, nameof(MyDetector), () => ScanOnceAsync(ct));
//
// The detector keeps running when a scan iteration throws — same behaviour as the bare `catch {}`
// it replaces — but the failure is now counted and logged instead of vanishing.
public static class DetectorScanScope
{
    // Overload for the many detectors that already hold an IServiceScopeFactory (for the
    // scope-per-write persistence pattern) but take no IDetectorDiagnostics in their constructor.
    // It lets those detectors adopt diagnostics without a constructor/DI change. Scan loops tick
    // every 15-60 s, so resolving a singleton through a scope per iteration is not a hot path.
    public static async Task RunAsync(
        IServiceScopeFactory scopeFactory,
        string detectorName,
        Func<Task> scan)
    {
        IDetectorDiagnostics? diagnostics = null;
        try
        {
            using var scope = scopeFactory.CreateScope();
            diagnostics = scope.ServiceProvider.GetService<IDetectorDiagnostics>();
        }
        catch (ObjectDisposedException)
        {
            // Container torn down during shutdown — fall through to the no-diagnostics path.
        }

        if (diagnostics is null)
        {
            // Diagnostics unavailable (not registered, or shutting down): preserve the original
            // "never let a scan failure kill the monitor" behaviour rather than crashing.
            try { await scan().ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception) { }
            return;
        }

        await RunAsync(diagnostics, detectorName, scan).ConfigureAwait(false);
    }

    public static async Task RunAsync(
        IDetectorDiagnostics diagnostics,
        string detectorName,
        Func<Task> scan)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            await scan().ConfigureAwait(false);
            sw.Stop();
            diagnostics.RecordScanCompleted(detectorName, sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            // Shutdown, not a failure — must propagate so the caller's loop exits.
            throw;
        }
        catch (Exception ex)
        {
            sw.Stop();
            diagnostics.RecordScanFailed(detectorName, ex.GetType().Name, ex);
        }
    }

    // Resolve once per scan and reuse across the inner loop. Creating a scope per process would
    // mean thousands of scope allocations every sweep, so this is deliberately hoisted out.
    public static IDetectorDiagnostics? ResolveDiagnostics(IServiceScopeFactory scopeFactory)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            return scope.ServiceProvider.GetService<IDetectorDiagnostics>();
        }
        catch (ObjectDisposedException)
        {
            return null;
        }
    }

    // Per-item wrapper for the inner "foreach process" loops. Counts the outcome without logging
    // (see IDetectorDiagnostics) and never rethrows, preserving the existing behaviour where one
    // inaccessible process does not abort the sweep over the remaining ones.
    public static async Task RunItemAsync(
        IDetectorDiagnostics? diagnostics,
        string detectorName,
        Func<Task> inspectItem)
    {
        try
        {
            await inspectItem().ConfigureAwait(false);
            diagnostics?.RecordItemInspected(detectorName);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception)
        {
            diagnostics?.RecordItemSkipped(detectorName);
        }
    }

    public static void Run(
        IDetectorDiagnostics diagnostics,
        string detectorName,
        Action scan)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            scan();
            sw.Stop();
            diagnostics.RecordScanCompleted(detectorName, sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            sw.Stop();
            diagnostics.RecordScanFailed(detectorName, ex.GetType().Name, ex);
        }
    }
}
