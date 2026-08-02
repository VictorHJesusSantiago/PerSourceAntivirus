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

// Phase 15-17 network/kernel protections, privacy, security auditing and investigation.
// Extracted from the former ~580-line AddInfrastructureServices (ADR-002). Registration
// order within and across modules is preserved exactly as it was.
internal static class NetworkAndAuditServices
{
    public static IServiceCollection AddNetworkAndAuditServices(this IServiceCollection services, IConfiguration configuration, InfrastructureBuildContext ctx)
    {
        // Phase 15 â€” Network security + kernel protections
        services.AddSingleton<INetworkIdsDetector, SharpPcapIdsDetector>();
        services.AddScoped<INetworkIdsAlertRepository, NetworkIntrusionAlertRepository>();
        services.AddSingleton<IArpSpoofingDetector, ArpSpoofingDetector>();
        services.AddScoped<IArpSpoofingAlertRepository, ArpSpoofingAlertRepository>();
        services.AddSingleton<ILlmnrPoisoningDetector, LlmnrPoisoningDetector>();
        services.AddScoped<ILlmnrPoisoningAlertRepository, LlmnrPoisoningAlertRepository>();
        services.AddSingleton<IKeyloggerDetector, KeyloggerDetector>();
        services.AddScoped<IKeyloggerAlertRepository, KeyloggerAlertRepository>();
        services.AddSingleton<ISafeFolderService, SafeFolderService>();
        services.AddScoped<ISafeFolderViolationRepository, SafeFolderViolationRepository>();
        services.AddSingleton<IBootExecuteService, BootExecuteService>();
        services.AddSingleton<IDnsSinkhole, DnsSinkholeService>();
        services.AddSingleton<INdisInspectionService, NdisInspectionService>();

        // Phase 16 â€” Network detection (items 36â€“40)
        services.AddSingleton<IPortScanDetector, PortScanDetector>();
        services.AddScoped<IPortScanAlertRepository, PortScanAlertRepository>();
        services.AddSingleton<ISmbLateralMovementDetector, SmbLateralMovementDetector>();
        services.AddScoped<ISmbLateralMovementAlertRepository, SmbLateralMovementAlertRepository>();
        services.AddScoped<ITlsCertAlertRepository, TlsCertAlertRepository>();
        services.AddSingleton<IEnhancedBeaconingDetector, EnhancedBeaconingDetector>();
        services.AddScoped<IBeaconingAnalysisRepository, BeaconingAnalysisRepository>();
        services.AddSingleton<IWpadAbuseDetector, WpadAbuseDetector>();
        services.AddScoped<IWpadAbuseAlertRepository, WpadAbuseAlertRepository>();

        // Phase 16 â€” Ransomware prevention (items 41â€“43)
        services.AddSingleton<IVssRollbackService, PerSourceAntivirus.Infrastructure.Ransomware.VssRollbackService>();
        services.AddScoped<IVssSnapshotRepository, PerSourceAntivirus.Infrastructure.Ransomware.VssSnapshotRepository>();
        services.AddSingleton<IScreenLockerDetector, PerSourceAntivirus.Infrastructure.Privacy.ScreenLockerDetector>();
        services.AddScoped<IScreenLockerAlertRepository, PerSourceAntivirus.Infrastructure.Privacy.ScreenLockerAlertRepository>();
        services.AddSingleton<IMbrRealtimeProtection, PerSourceAntivirus.Infrastructure.Kernel.MbrRealtimeProtectionService>();
        services.AddScoped<IMbrWriteAttemptRepository, PerSourceAntivirus.Infrastructure.Kernel.MbrWriteAttemptRepository>();

        // Phase 16 â€” Privacy (items 44â€“48)
        services.AddSingleton<IClipboardHijackDetector, PerSourceAntivirus.Infrastructure.Privacy.ClipboardHijackDetector>();
        services.AddScoped<IClipboardHijackAlertRepository, PerSourceAntivirus.Infrastructure.Privacy.ClipboardHijackAlertRepository>();
        services.AddSingleton<IWebcamAccessMonitor, PerSourceAntivirus.Infrastructure.Privacy.WebcamAccessMonitor>();
        services.AddScoped<IWebcamAccessRepository, PerSourceAntivirus.Infrastructure.Privacy.WebcamAccessRepository>();
        services.AddSingleton<IMicrophoneAccessMonitor, PerSourceAntivirus.Infrastructure.Privacy.MicrophoneAccessMonitor>();
        services.AddScoped<IMicrophoneAccessRepository, PerSourceAntivirus.Infrastructure.Privacy.MicrophoneAccessRepository>();
        services.AddSingleton<IScreenCaptureDetector, PerSourceAntivirus.Infrastructure.Privacy.ScreenCaptureDetector>();
        services.AddScoped<IScreenCaptureAlertRepository, PerSourceAntivirus.Infrastructure.Privacy.ScreenCaptureAlertRepository>();

        // Phase 16 â€” Scanners + audit (items 49â€“55)
        services.AddSingleton<ISensitiveDataScanner, PerSourceAntivirus.Infrastructure.Security.SensitiveDataScanner>();
        services.AddScoped<ISensitiveDataFindingRepository, PerSourceAntivirus.Infrastructure.Security.SensitiveDataFindingRepository>();
        services.AddSingleton<IInstalledSoftwareScanner, PerSourceAntivirus.Infrastructure.Security.InstalledSoftwareScanner>();
        services.AddScoped<IVulnerableSoftwareAlertRepository, PerSourceAntivirus.Infrastructure.Security.VulnerableSoftwareAlertRepository>();
        services.AddSingleton<ISecurityPostureChecker, PerSourceAntivirus.Infrastructure.Security.SecurityPostureChecker>();
        services.AddScoped<ISecurityPostureIssueRepository, PerSourceAntivirus.Infrastructure.Security.SecurityPostureIssueRepository>();
        services.AddSingleton<IAutostartAuditor, PerSourceAntivirus.Infrastructure.Security.AutostartAuditor>();
        services.AddScoped<IAutostartEntryRepository, PerSourceAntivirus.Infrastructure.Security.AutostartEntryRepository>();
        services.AddSingleton<IServiceAuditor, PerSourceAntivirus.Infrastructure.Security.ServiceAuditor>();
        services.AddScoped<IServiceAuditFindingRepository, PerSourceAntivirus.Infrastructure.Security.ServiceAuditFindingRepository>();
        services.AddSingleton<IUserAccountAuditor, PerSourceAntivirus.Infrastructure.Security.UserAccountAuditor>();
        services.AddScoped<IUserAccountAuditFindingRepository, PerSourceAntivirus.Infrastructure.Security.UserAccountAuditFindingRepository>();
        services.AddSingleton<IOpenPortScanner, PerSourceAntivirus.Infrastructure.Security.OpenPortScanner>();
        services.AddScoped<IOpenPortInfoRepository, PerSourceAntivirus.Infrastructure.Security.OpenPortInfoRepository>();

        // Phase 17 â€” Event history + investigation + threat intel (items 56â€“62)
        services.AddScoped<IProcessCreationEventRepository, PerSourceAntivirus.Infrastructure.Etw.ProcessCreationEventRepository>();
        services.AddScoped<IFileActivityEventRepository, PerSourceAntivirus.Infrastructure.Etw.FileActivityEventRepository>();
        services.AddScoped<IRegistryActivityEventRepository, PerSourceAntivirus.Infrastructure.Etw.RegistryActivityEventRepository>();
        services.AddScoped<IEventHistoryService, PerSourceAntivirus.Infrastructure.Etw.EventHistoryService>();
        services.AddScoped<IAttackTimelineService, PerSourceAntivirus.Infrastructure.Investigation.AttackTimelineService>();
        services.AddScoped<IHuntQueryService, PerSourceAntivirus.Infrastructure.Investigation.HuntQueryService>();
        services.AddSingleton<IMitreAttackService, PerSourceAntivirus.Infrastructure.Investigation.MitreAttackService>();
        services.AddScoped<ICustomIocRepository, PerSourceAntivirus.Infrastructure.ThreatIntel.CustomIocRepository>();
        services.AddScoped<ICustomIocService, PerSourceAntivirus.Infrastructure.ThreatIntel.CustomIocService>();
        services.AddScoped<IStixFeedSourceRepository, PerSourceAntivirus.Infrastructure.ThreatIntel.StixFeedSourceRepository>();
        services.AddScoped<IStixIocRepository, PerSourceAntivirus.Infrastructure.ThreatIntel.StixIocRepository>();
        services.AddScoped<IStixFeedImporter>(sp => new PerSourceAntivirus.Infrastructure.ThreatIntel.StixFeedImporter(
            sp.GetRequiredService<IStixFeedSourceRepository>(),
            sp.GetRequiredService<IStixIocRepository>(),
            sp.GetRequiredService<IHttpClientFactory>()));
        services.AddScoped<IAlertTriageRepository, PerSourceAntivirus.Infrastructure.Investigation.AlertTriageRepository>();
        services.AddScoped<IIncidentRepository, PerSourceAntivirus.Infrastructure.Investigation.IncidentRepository>();
        services.AddScoped<IAlertTriageService, PerSourceAntivirus.Infrastructure.Investigation.AlertTriageService>();

        // Phase 17 â€” Process mitigation + security enforcement (items 70â€“74)
        services.AddSingleton<IProcessMitigationService, PerSourceAntivirus.Infrastructure.Security.ProcessMitigationService>();
        services.AddScoped<ICfgViolationAlertRepository, PerSourceAntivirus.Infrastructure.Security.CfgViolationAlertRepository>();
        services.AddSingleton<IAmsiBypassDetector, PerSourceAntivirus.Infrastructure.Security.AmsiBypassDetector>();
        services.AddScoped<IAmsiBypassAlertRepository, PerSourceAntivirus.Infrastructure.Security.AmsiBypassAlertRepository>();
        services.AddSingleton<IPowerShellClmEnforcer, PerSourceAntivirus.Infrastructure.Security.PowerShellClmEnforcer>();

        return services;
    }
}
