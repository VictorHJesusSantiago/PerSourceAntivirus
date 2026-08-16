using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Diagnostics;

public static class DetectorScanScope
{
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
        }

        if (diagnostics is null)
        {
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
            throw;
        }
        catch (Exception ex)
        {
            sw.Stop();
            diagnostics.RecordScanFailed(detectorName, ex.GetType().Name, ex);
        }
    }

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
