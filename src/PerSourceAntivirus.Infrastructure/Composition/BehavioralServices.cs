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

// Phase 18 behavioral analysis, notifications, reporting, forensics and app whitelisting.
// Extracted from the former ~580-line AddInfrastructureServices (ADR-002). Registration
// order within and across modules is preserved exactly as it was.
internal static class BehavioralServices
{
    public static IServiceCollection AddBehavioralServices(this IServiceCollection services, IConfiguration configuration, InfrastructureBuildContext ctx)
    {
        // Phase 18 â€” Behavioral analysis (items 75â€“78)
        services.AddSingleton<IApiCallSequenceAnalyzer, ApiCallSequenceAnalyzer>();
        services.AddScoped<IApiCallSequenceAlertRepository, ApiCallSequenceAlertRepository>();
        services.AddSingleton<IParentChildAnomalyDetector, ParentChildAnomalyDetector>();
        services.AddScoped<IParentChildAnomalyAlertRepository, ParentChildAnomalyAlertRepository>();
        services.AddSingleton<IProcessCommandLineAnalyzer, ProcessCommandLineAnalyzer>();
        services.AddScoped<IProcessCommandLineAlertRepository, ProcessCommandLineAlertRepository>();
        services.AddSingleton<INetworkBehaviorProfiler, NetworkBehaviorProfiler>();
        services.AddScoped<INetworkBehaviorProfileRepository, NetworkBehaviorProfileRepository>();
        services.AddScoped<INetworkBehaviorAlertRepository, NetworkBehaviorAlertRepository>();

        // Phase 18 â€” Notifications + scan profiles (items 80, 84)
        services.AddScoped<INotificationRecordRepository, PerSourceAntivirus.Infrastructure.Notifications.NotificationRecordRepository>();
        services.AddSingleton<INotificationCenter, PerSourceAntivirus.Infrastructure.Notifications.NotificationCenter>();
        services.AddScoped<IScanProfileRepository, PerSourceAntivirus.Infrastructure.Scanning.ScanProfileRepository>();
        services.AddScoped<IScanProfileService, PerSourceAntivirus.Infrastructure.Scanning.ScanProfileService>();

        // Phase 18 â€” Supporting services (items 85â€“86)
        services.AddSingleton<ICpuIdleMonitor, PerSourceAntivirus.Infrastructure.SystemIntegration.CpuIdleMonitor>();
        services.AddSingleton<IGamingModeDetector, PerSourceAntivirus.Infrastructure.SystemIntegration.GamingModeDetector>();

        // Phase 18 â€” Reporting (item 87)
        services.AddScoped<IThreatReportRepository, ThreatReportRepository>();
        services.AddScoped<IReportGenerator, ReportGenerator>();
        services.AddScoped<IAlertAggregatorService, AlertAggregatorService>();
        services.AddScoped<IThreatTrendService, ThreatTrendService>();

        // Phase 18 â€” System integration (items 91â€“95)
        services.AddSingleton<IWindowsEventLogWriter, InfraSystem.WindowsEventLogWriter>();
        services.AddSingleton<IEtwCustomProvider, InfraSystem.EtwCustomProvider>();
        services.AddSingleton<IWmiCustomProvider, InfraSystem.WmiCustomProvider>();
        services.AddSingleton<IAppLockerIntegration, InfraSystem.AppLockerIntegration>();
        services.AddSingleton<IVssBackupService, InfraSystem.VssBackupService>();

        // Phase 18 â€” Forensics (items 96â€“98)
        services.AddScoped<IMemoryDumpResultRepository, MemoryDumpResultRepository>();
        services.AddSingleton<IMemoryForensicsService, MemoryForensicsService>();
        services.AddScoped<IFirmwareVariableSnapshotRepository, FirmwareVariableSnapshotRepository>();
        services.AddSingleton<IFirmwareVariableMonitor, FirmwareVariableMonitor>();
        services.AddScoped<IHypervisorDetectionResultRepository, HypervisorDetectionResultRepository>();
        services.AddSingleton<IHypervisorDetector, HypervisorDetector>();

        // Phase 18 â€” Security (items 99â€“100)
        services.AddScoped<IKernelPatchGuardAlertRepository, PerSourceAntivirus.Infrastructure.Security.KernelPatchGuardAlertRepository>();
        services.AddSingleton<IKernelPatchGuardMonitor, PerSourceAntivirus.Infrastructure.Security.KernelPatchGuardMonitor>();
        services.AddScoped<ISupplyChainAlertRepository, PerSourceAntivirus.Infrastructure.Security.SupplyChainAlertRepository>();
        services.AddSingleton<ISupplyChainDetector, PerSourceAntivirus.Infrastructure.Security.SupplyChainDetector>();

        // Phase 17 â€” App whitelisting + sandbox + PUA + script sandbox + browser (items 63â€“69)
        services.AddScoped<IAppWhitelistRepository, PerSourceAntivirus.Infrastructure.Security.AppWhitelistRepository>();
        services.AddScoped<IAppWhitelistService, PerSourceAntivirus.Infrastructure.Security.AppWhitelistService>();
        services.AddSingleton<IAppContainerSandboxRunner, PerSourceAntivirus.Infrastructure.Sandbox.AppContainerSandboxRunner>();
        services.AddSingleton<IPuaDetector, PerSourceAntivirus.Infrastructure.Security.PuaDetector>();
        services.AddScoped<IPuaAlertRepository, PerSourceAntivirus.Infrastructure.Security.PuaAlertRepository>();
        services.AddScoped<IScriptSandboxService, PerSourceAntivirus.Infrastructure.Sandbox.ScriptSandboxService>();
        services.AddScoped<IScriptSandboxResultRepository, PerSourceAntivirus.Infrastructure.Sandbox.ScriptSandboxResultRepository>();
        services.AddSingleton<IBrowserExtensionAuditor, PerSourceAntivirus.Infrastructure.Browser.BrowserExtensionAuditor>();
        services.AddScoped<IBrowserExtensionFindingRepository, PerSourceAntivirus.Infrastructure.Browser.BrowserExtensionFindingRepository>();
        services.AddSingleton<IBrowserCredentialMonitor, PerSourceAntivirus.Infrastructure.Browser.BrowserCredentialMonitor>();
        services.AddScoped<IBrowserCredentialAccessAlertRepository, PerSourceAntivirus.Infrastructure.Browser.BrowserCredentialAccessAlertRepository>();

        return services;
    }
}
