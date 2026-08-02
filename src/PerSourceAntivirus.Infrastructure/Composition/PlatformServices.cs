using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Scans;
using PerSourceAntivirus.Infrastructure.Amsi;
using PerSourceAntivirus.Infrastructure.Archive;
using PerSourceAntivirus.Infrastructure.ComHijack;
using PerSourceAntivirus.Infrastructure.Config;
using PerSourceAntivirus.Infrastructure.Cryptojacking;
using PerSourceAntivirus.Infrastructure.Dga;
using PerSourceAntivirus.Infrastructure.DllHijack;
using PerSourceAntivirus.Infrastructure.Email;
using PerSourceAntivirus.Infrastructure.Emulation;
using PerSourceAntivirus.Infrastructure.Etw;
using PerSourceAntivirus.Infrastructure.Fileless;
using PerSourceAntivirus.Infrastructure.Files;
using PerSourceAntivirus.Infrastructure.LolBin;
using PerSourceAntivirus.Infrastructure.Mbr;
using PerSourceAntivirus.Infrastructure.Metadata;
using PerSourceAntivirus.Infrastructure.Minifilter;
using PerSourceAntivirus.Infrastructure.Ransomware;
using PerSourceAntivirus.Infrastructure.Persistence;
using PerSourceAntivirus.Infrastructure.Network;
using PerSourceAntivirus.Infrastructure.Office;
using PerSourceAntivirus.Infrastructure.Packing;
using PerSourceAntivirus.Infrastructure.Pdf;
using PerSourceAntivirus.Infrastructure.Pe;
using PerSourceAntivirus.Infrastructure.Process;
using PerSourceAntivirus.Infrastructure.ProcessInjection;
using PerSourceAntivirus.Infrastructure.Reputation;
using PerSourceAntivirus.Infrastructure.Rootkit;
using PerSourceAntivirus.Infrastructure.Sandbox;
using PerSourceAntivirus.Infrastructure.Scheduling;
using PerSourceAntivirus.Infrastructure.Scripts;
using PerSourceAntivirus.Infrastructure.SelfIntegrity;
using PerSourceAntivirus.Infrastructure.Siem;
using PerSourceAntivirus.Infrastructure.Signatures;
using PerSourceAntivirus.Infrastructure.Signing;
using PerSourceAntivirus.Infrastructure.Steganography;
using PerSourceAntivirus.Infrastructure.ThreatFeeds;
using PerSourceAntivirus.Infrastructure.Tls;
using PerSourceAntivirus.Infrastructure.Uefi;
using PerSourceAntivirus.Infrastructure.Updates;
using PerSourceAntivirus.Infrastructure.Wmi;
using PerSourceAntivirus.Infrastructure.Kernel;
using PerSourceAntivirus.Infrastructure.Behavioral;
using PerSourceAntivirus.Infrastructure.Forensics;
using PerSourceAntivirus.Infrastructure.Reporting;
using PerSourceAntivirus.Infrastructure.Wsc;
using PerSourceAntivirus.Infrastructure.Yara;
using InfraSystem = PerSourceAntivirus.Infrastructure.SystemIntegration;
using PerSourceAntivirus.Infrastructure.Composition;

namespace PerSourceAntivirus.Infrastructure;

// Threat feeds, MBR/ETW/sandbox, ransomware, kernel, ML, WFP, SIEM, TLS, COM.
// Extracted from the former ~580-line AddInfrastructureServices (ADR-002). Registration
// order within and across modules is preserved exactly as it was.
internal static class PlatformServices
{
    public static IServiceCollection AddPlatformServices(this IServiceCollection services, IConfiguration configuration, InfrastructureBuildContext ctx)
    {
        // Threat intelligence feed updaters (Group 3)
        services.AddSingleton<IThreatFeedUpdater>(sp => new FeodoTrackerUpdater(
            ctx.BlocklistProvider, ctx.IpBlocklistFile, sp.GetRequiredService<IHttpClientFactory>()));
        services.AddSingleton<IThreatFeedUpdater>(sp => new MalwareBazaarUpdater(
            ctx.LocalReputation, ctx.LocalHashFile, sp.GetRequiredService<IHttpClientFactory>()));
        services.AddSingleton<IThreatFeedUpdater>(sp => new UrlhausUpdater(
            ctx.DomainBlocklist, ctx.DomainBlocklistFile, sp.GetRequiredService<IHttpClientFactory>()));

        // MBR protection (Group 4)
        services.AddSingleton<IMbrProtectionService, MbrProtectionService>();
        services.AddScoped<IMbrSnapshotRepository, MbrSnapshotRepository>();

        // ETW monitor (Group 4) â€” Windows-only, requires admin
        services.AddSingleton<IEtwMonitor, EtwMonitor>();

        // Sandbox runner (Group 4) â€” Job Object based, Windows-only
        services.AddSingleton<ISandboxRunner, JobObjectSandboxRunner>();

        // Process memory scanner â€” YARA scan over live process address space
        services.AddSingleton<IProcessMemoryScanner, ProcessMemoryScanner>();

        // Ransomware detection â€” honeypot + mass encryption + VSS watch
        services.AddSingleton<IHoneypotManager, HoneypotManager>();
        services.AddSingleton<IRansomwareMonitor, RansomwareMonitor>();
        services.AddScoped<IHoneypotRepository, HoneypotRepository>();
        services.AddScoped<IRansomwareAlertRepository, RansomwareAlertRepository>();

        // Minifilter communicator â€” connects to kernel driver port \PSAVScanPort
        services.AddSingleton<IMinifilterMonitor, MinifilterCommunicator>();

        // Kernel event monitor â€” connects to \PSAVEventPort for process/image callbacks
        services.AddSingleton<IKernelEventMonitor, KernelEventCommunicator>();

        // ML PE classifier â€” tries to load ONNX model, falls back to heuristic
        services.AddSingleton<IPeMlClassifier>(new PerSourceAntivirus.Infrastructure.Pe.OnnxPeMlClassifier(ctx.ModelsDirectory));
        services.AddScoped<IPeMlPredictionRepository, PeMlPredictionRepository>();

        // WFP network blocker â€” blocks IPs at Windows Filtering Platform level
        services.AddSingleton<IWfpBlocker, PerSourceAntivirus.Infrastructure.Network.WfpBlocker>();
        services.AddScoped<IWfpBlockRepository, WfpBlockRepository>();

        // Scheduled scan background service
        services.AddHostedService<ScanSchedulerService>();

        // Rootkit scanner + repository (Group 7)
        services.AddSingleton<IRootkitScanner, RootkitScanner>();
        services.AddScoped<IRootkitFindingRepository, RootkitFindingRepository>();

        // Shellcode / exploit memory detector (Group 13)
        services.AddSingleton<IShellcodeDetector, ShellcodeDetector>();
        services.AddScoped<IExploitFindingRepository, ExploitFindingRepository>();

        // UEFI firmware scanner + repository (Group 14)
        services.AddSingleton<IUefiScanner, UefiScanner>();
        services.AddScoped<IUefiFindingRepository, UefiFindingRepository>();

        // Auto-updater (Group 8)
        services.AddSingleton<IAutoUpdater>(sp => new SignatureAutoUpdater(
            sp.GetRequiredService<IEnumerable<IThreatFeedUpdater>>(),
            sp.GetRequiredService<IYaraRulesUpdater>(),
            sp.GetRequiredService<IBlocklistUpdater>()));

        // WMI persistence scanner + repository (Group 10)
        services.AddSingleton<IWmiPersistenceScanner, WmiPersistenceScanner>();
        services.AddScoped<IWmiPersistenceAlertRepository, WmiPersistenceAlertRepository>();

        // Self-integrity service (Group 11)
        services.AddSingleton<ISelfIntegrityService, SelfIntegrityService>();

        // Enhanced sandbox with ETW behavioral analysis (Group 16)
        services.AddSingleton<IEnhancedSandboxRunner, EtwEnhancedSandboxRunner>();

        // SIEM / telemetry exporter (Group 15)
        var siemProtocol = configuration["Siem:Protocol"] is string p && Enum.TryParse<SiemProtocol>(p, out var proto) ? proto : SiemProtocol.Disabled;
        var siemHost = configuration["Siem:Host"] ?? "127.0.0.1";
        var siemPort = int.TryParse(configuration["Siem:Port"], out var sp2) ? sp2 : -1;
        var siemApiKey = configuration["Siem:ApiKey"];
        services.AddSingleton<ISiemExporter>(sp => new SyslogCefExporter(
            siemProtocol, siemHost, siemPort, siemApiKey, sp.GetRequiredService<IHttpClientFactory>()));

        // TLS inspection proxy + repository (Group 9)
        services.AddSingleton<ITlsInspector, LocalTlsProxy>();
        services.AddScoped<ITlsInspectionEventRepository, TlsInspectionEventRepository>();

        // COM hijack / DLL sideloading monitor + repository (Group 17)
        services.AddSingleton<IComHijackMonitor, ComHijackMonitor>();
        services.AddScoped<IComHijackAlertRepository, ComHijackAlertRepository>();

        return services;
    }
}
