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

internal static class PlatformServices
{
    public static IServiceCollection AddPlatformServices(this IServiceCollection services, IConfiguration configuration, InfrastructureBuildContext ctx)
    {
        services.AddSingleton<IThreatFeedUpdater>(sp => new FeodoTrackerUpdater(
            ctx.BlocklistProvider, ctx.IpBlocklistFile, sp.GetRequiredService<IHttpClientFactory>()));
        services.AddSingleton<IThreatFeedUpdater>(sp => new MalwareBazaarUpdater(
            ctx.LocalReputation, ctx.LocalHashFile, sp.GetRequiredService<IHttpClientFactory>()));
        services.AddSingleton<IThreatFeedUpdater>(sp => new UrlhausUpdater(
            ctx.DomainBlocklist, ctx.DomainBlocklistFile, sp.GetRequiredService<IHttpClientFactory>()));

        services.AddSingleton<IMbrProtectionService, MbrProtectionService>();
        services.AddScoped<IMbrSnapshotRepository, MbrSnapshotRepository>();

        services.AddSingleton<IEtwMonitor, EtwMonitor>();

        services.AddSingleton<ISandboxRunner, JobObjectSandboxRunner>();

        services.AddSingleton<IProcessMemoryScanner, ProcessMemoryScanner>();

        services.AddSingleton<IHoneypotManager, HoneypotManager>();
        services.AddSingleton<IRansomwareMonitor, RansomwareMonitor>();
        services.AddScoped<IHoneypotRepository, HoneypotRepository>();
        services.AddScoped<IRansomwareAlertRepository, RansomwareAlertRepository>();

        services.AddSingleton<IMinifilterMonitor, MinifilterCommunicator>();

        services.AddSingleton<IKernelEventMonitor, KernelEventCommunicator>();

        services.AddSingleton<IPeMlClassifier>(new PerSourceAntivirus.Infrastructure.Pe.OnnxPeMlClassifier(ctx.ModelsDirectory));
        services.AddScoped<IPeMlPredictionRepository, PeMlPredictionRepository>();

        services.AddSingleton<IWfpBlocker, PerSourceAntivirus.Infrastructure.Network.WfpBlocker>();
        services.AddScoped<IWfpBlockRepository, WfpBlockRepository>();

        services.AddHostedService<ScanSchedulerService>();

        services.AddSingleton<IRootkitScanner, RootkitScanner>();
        services.AddScoped<IRootkitFindingRepository, RootkitFindingRepository>();

        services.AddSingleton<IShellcodeDetector, ShellcodeDetector>();
        services.AddScoped<IExploitFindingRepository, ExploitFindingRepository>();

        services.AddSingleton<IUefiScanner, UefiScanner>();
        services.AddScoped<IUefiFindingRepository, UefiFindingRepository>();

        services.AddSingleton<IAutoUpdater>(sp => new SignatureAutoUpdater(
            sp.GetRequiredService<IEnumerable<IThreatFeedUpdater>>(),
            sp.GetRequiredService<IYaraRulesUpdater>(),
            sp.GetRequiredService<IBlocklistUpdater>()));

        services.AddSingleton<IWmiPersistenceScanner, WmiPersistenceScanner>();
        services.AddScoped<IWmiPersistenceAlertRepository, WmiPersistenceAlertRepository>();

        services.AddSingleton<ISelfIntegrityService, SelfIntegrityService>();

        services.AddSingleton<IEnhancedSandboxRunner, EtwEnhancedSandboxRunner>();

        var siemProtocol = configuration["Siem:Protocol"] is string p && Enum.TryParse<SiemProtocol>(p, out var proto) ? proto : SiemProtocol.Disabled;
        var siemHost = configuration["Siem:Host"] ?? "127.0.0.1";
        var siemPort = int.TryParse(configuration["Siem:Port"], out var sp2) ? sp2 : -1;
        var siemApiKey = configuration["Siem:ApiKey"];
        services.AddSingleton<ISiemExporter>(sp => new SyslogCefExporter(
            siemProtocol, siemHost, siemPort, siemApiKey, sp.GetRequiredService<IHttpClientFactory>()));

        services.AddSingleton<ITlsInspector, LocalTlsProxy>();
        services.AddScoped<ITlsInspectionEventRepository, TlsInspectionEventRepository>();

        services.AddSingleton<IComHijackMonitor, ComHijackMonitor>();
        services.AddScoped<IComHijackAlertRepository, ComHijackAlertRepository>();

        return services;
    }
}
