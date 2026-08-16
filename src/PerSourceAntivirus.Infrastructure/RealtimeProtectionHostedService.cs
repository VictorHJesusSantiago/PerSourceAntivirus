using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure;

public sealed class RealtimeProtectionHostedService(
    IServiceProvider services,
    IConfiguration configuration,
    IDetectorDiagnostics diagnostics,
    ILogger<RealtimeProtectionHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!(bool.TryParse(configuration["RealtimeProtection:Enabled"], out var enabled) && enabled))
        {
            logger.LogInformation("Realtime protection disabled (RealtimeProtection:Enabled is not true) — no detectors started.");
            return;
        }

        WirePlaybookResponses(stoppingToken);

        var tasks = new List<Task>();

        tasks.Add(RunAsync("ArpSpoofingDetector", () => services.GetRequiredService<IArpSpoofingDetector>().StartMonitoringAsync(null, stoppingToken)));
        tasks.Add(RunAsync("DnsTunnelingDetector", () => services.GetRequiredService<IDnsTunnelingDetector>().StartMonitoringAsync(null, stoppingToken)));
        tasks.Add(RunAsync("EnhancedBeaconingDetector", () => services.GetRequiredService<IEnhancedBeaconingDetector>().StartMonitoringAsync(null, stoppingToken)));
        tasks.Add(RunAsync("GeoIpEnforcementDetector", () => services.GetRequiredService<IGeoIpEnforcementDetector>().StartMonitoringAsync(null, stoppingToken)));
        tasks.Add(RunAsync("LlmnrPoisoningDetector", () => services.GetRequiredService<ILlmnrPoisoningDetector>().StartMonitoringAsync(null, stoppingToken)));
        tasks.Add(RunAsync("NetworkIdsDetector", () => services.GetRequiredService<INetworkIdsDetector>().StartMonitoringAsync(null, stoppingToken)));

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

        if (!stoppingToken.IsCancellationRequested)
            logger.LogError("All realtime detectors have stopped while protection was still enabled.");
    }

    private void WirePlaybookResponses(CancellationToken ct)
    {
        var engine = services.GetRequiredService<IResponsePlaybookEngine>();

        void Dispatch(string alertType, int severity, int? pid, string? filePath)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await engine.EvaluateAsync(new PlaybookTriggerContext(alertType, severity, pid, filePath), ct)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Playbook evaluation failed for {AlertType}.", alertType);
                }
            }, ct);
        }

        Subscribe<ICryptojackingDetector, CryptojackingAlertEventArgs>(
            d => h => d.AlertDetected += h,
            e => Dispatch("Cryptojacking", e.Alert.Severity, e.Alert.ProcessId, null));

        Subscribe<IDllHijackDetector, DllHijackAlertEventArgs>(
            d => h => d.AlertDetected += h,
            e => Dispatch("DllHijack", e.Alert.Severity, e.Alert.ProcessId, e.Alert.LoadedDllPath));

        Subscribe<IUnsignedBinaryDetector, UnsignedBinaryAlertEventArgs>(
            d => h => d.AlertDetected += h,
            e => Dispatch("UnsignedBinary", e.Alert.Severity, e.Alert.ProcessId, e.Alert.FilePath));

        Subscribe<ICertificateTrustDetector, CertificateTrustAlertEventArgs>(
            d => h => d.AlertDetected += h,
            e => Dispatch("BlacklistedCertificate", e.Alert.Severity, e.Alert.ProcessId, e.Alert.FilePath));

        Subscribe<IHeapSprayDetector, HeapSprayAlertEventArgs>(
            d => h => d.AlertDetected += h,
            e => Dispatch("HeapSpray", e.Alert.Severity, e.Alert.ProcessId, null));

        Subscribe<IProcessHollowingDetector, ProcessHollowingAlertEventArgs>(
            d => h => d.AlertDetected += h,
            e => Dispatch("ProcessHollowing", e.Alert.Severity, e.Alert.InjectorProcessId, null));
    }

    private void Subscribe<TDetector, TArgs>(
        Func<TDetector, Action<EventHandler<TArgs>>> attach,
        Action<TArgs> onAlert)
        where TDetector : notnull
    {
        try
        {
            var detector = services.GetRequiredService<TDetector>();
            attach(detector)((_, args) =>
            {
                try { onAlert(args); }
                catch (Exception ex) { logger.LogWarning(ex, "Alert handler failed for {Detector}.", typeof(TDetector).Name); }
            });
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not wire playbook responses for {Detector}.", typeof(TDetector).Name);
        }
    }

    private async Task RunAsync(string detectorName, Func<Task> start)
    {
        try
        {
            await start().ConfigureAwait(false);

            logger.LogWarning("Detector {Detector} stopped monitoring unexpectedly (returned without cancellation).", detectorName);
            diagnostics.RecordScanFailed(detectorName, "StoppedUnexpectedly");
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Detector {Detector} stopped unexpectedly.", detectorName);
            diagnostics.RecordScanFailed(detectorName, ex.GetType().Name, ex);
        }
    }
}
