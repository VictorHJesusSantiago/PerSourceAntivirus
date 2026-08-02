using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure;

// [AUDIT FIX — CRITICAL] Every detector below exposes StartMonitoringAsync but, before this
// service existed, nothing in the codebase ever called it: 42 fully-implemented, DI-registered
// real-time detectors (process injection, network, privacy, behavioral, self-protection) were
// dead code at runtime — reachable only by unit tests. The GUI's "Realtime Protection" toggle
// (Settings > RealtimeProtection:Enabled) persisted a value that nothing ever read, so it had
// zero effect. This service is the missing composition root: it reads that same flag and, when
// enabled, starts every detector as an independently-faulted background task so one detector's
// failure (e.g. missing admin rights for a WFP/ETW-based one) never stops the others or the host.
//
// Defaults to disabled (matches the historical, silently-inert behavior) until an operator
// opts in via Settings — enabling 42 previously-dormant background loops as a side effect of an
// unrelated code change would be its own defect.
public sealed class RealtimeProtectionHostedService(
    IServiceProvider services,
    IConfiguration configuration,
    ILogger<RealtimeProtectionHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!(bool.TryParse(configuration["RealtimeProtection:Enabled"], out var enabled) && enabled))
        {
            logger.LogInformation("Realtime protection disabled (RealtimeProtection:Enabled is not true) — no detectors started.");
            return;
        }

        var tasks = new List<Task>();

        // Detectors that watch a specific capture device (null = library default device).
        tasks.Add(RunAsync("ArpSpoofingDetector", () => services.GetRequiredService<IArpSpoofingDetector>().StartMonitoringAsync(null, stoppingToken)));
        tasks.Add(RunAsync("DnsTunnelingDetector", () => services.GetRequiredService<IDnsTunnelingDetector>().StartMonitoringAsync(null, stoppingToken)));
        tasks.Add(RunAsync("EnhancedBeaconingDetector", () => services.GetRequiredService<IEnhancedBeaconingDetector>().StartMonitoringAsync(null, stoppingToken)));
        tasks.Add(RunAsync("GeoIpEnforcementDetector", () => services.GetRequiredService<IGeoIpEnforcementDetector>().StartMonitoringAsync(null, stoppingToken)));
        tasks.Add(RunAsync("LlmnrPoisoningDetector", () => services.GetRequiredService<ILlmnrPoisoningDetector>().StartMonitoringAsync(null, stoppingToken)));
        tasks.Add(RunAsync("NetworkIdsDetector", () => services.GetRequiredService<INetworkIdsDetector>().StartMonitoringAsync(null, stoppingToken)));

        // Detectors that only need a cancellation token.
        tasks.Add(RunAsync("AmsiBypassDetector", () => services.GetRequiredService<IAmsiBypassDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ApiCallSequenceAnalyzer", () => services.GetRequiredService<IApiCallSequenceAnalyzer>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("BrowserCredentialMonitor", () => services.GetRequiredService<IBrowserCredentialMonitor>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("CertificateTrustDetector", () => services.GetRequiredService<ICertificateTrustDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ClipboardHijackDetector", () => services.GetRequiredService<IClipboardHijackDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("CryptojackingDetector", () => services.GetRequiredService<ICryptojackingDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("DirectSyscallDetector", () => services.GetRequiredService<IDirectSyscallDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("DllHijackDetector", () => services.GetRequiredService<IDllHijackDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("FilelessDetector", () => services.GetRequiredService<IFilelessDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("HeapSprayDetector", () => services.GetRequiredService<IHeapSprayDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("HeavensGateDetector", () => services.GetRequiredService<IHeavensGateDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("KernelPatchGuardMonitor", () => services.GetRequiredService<IKernelPatchGuardMonitor>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("KeyloggerDetector", () => services.GetRequiredService<IKeyloggerDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("MicrophoneAccessMonitor", () => services.GetRequiredService<IMicrophoneAccessMonitor>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ModuleStompingDetector", () => services.GetRequiredService<IModuleStompingDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("NetworkBehaviorProfiler", () => services.GetRequiredService<INetworkBehaviorProfiler>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("NtdllUnhookingDetector", () => services.GetRequiredService<INtdllUnhookingDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ParentChildAnomalyDetector", () => services.GetRequiredService<IParentChildAnomalyDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("PortScanDetector", () => services.GetRequiredService<IPortScanDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ProcessCommandLineAnalyzer", () => services.GetRequiredService<IProcessCommandLineAnalyzer>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ProcessDoppelgangingDetector", () => services.GetRequiredService<IProcessDoppelgangingDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ProcessGhostingDetector", () => services.GetRequiredService<IProcessGhostingDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ProcessHollowingDetector", () => services.GetRequiredService<IProcessHollowingDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("PuaDetector", () => services.GetRequiredService<IPuaDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ReflectiveDllInjectionDetector", () => services.GetRequiredService<IReflectiveDllInjectionDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("SafeFolderService", () => services.GetRequiredService<ISafeFolderService>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ScreenCaptureDetector", () => services.GetRequiredService<IScreenCaptureDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("ScreenLockerDetector", () => services.GetRequiredService<IScreenLockerDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("SmbLateralMovementDetector", () => services.GetRequiredService<ISmbLateralMovementDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("StackPivotDetector", () => services.GetRequiredService<IStackPivotDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("SupplyChainDetector", () => services.GetRequiredService<ISupplyChainDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("TransactedHollowingDetector", () => services.GetRequiredService<ITransactedHollowingDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("UnsignedBinaryDetector", () => services.GetRequiredService<IUnsignedBinaryDetector>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("UsbDeviceControlService", () => services.GetRequiredService<IUsbDeviceControlService>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("WebcamAccessMonitor", () => services.GetRequiredService<IWebcamAccessMonitor>().StartMonitoringAsync(stoppingToken)));
        tasks.Add(RunAsync("WpadAbuseDetector", () => services.GetRequiredService<IWpadAbuseDetector>().StartMonitoringAsync(stoppingToken)));

        logger.LogInformation("Realtime protection enabled — starting {Count} detectors.", tasks.Count);
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    // Isolates one detector's failure from the rest: a thrown exception (missing admin rights,
    // unavailable native API, etc.) is logged and only that detector stops — it must never
    // propagate into Task.WhenAll and tear down every other detector alongside it.
    private async Task RunAsync(string detectorName, Func<Task> start)
    {
        try
        {
            await start().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Normal on shutdown.
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Detector {Detector} stopped unexpectedly.", detectorName);
        }
    }
}
