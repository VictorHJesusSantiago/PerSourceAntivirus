using Microsoft.EntityFrameworkCore;
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

namespace PerSourceAntivirus.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration configuration)
    {
        // [AUDIT FIX — Domain 15] Every HTTP-calling service used to hold its own `new HttpClient()`
        // (socket exhaustion + DNS that never refreshes) or share one process-wide static instance
        // (no handler rotation). IHttpClientFactory pools and recycles handlers; services now call
        // CreateClient() per request against these named policies.
        services.AddHttpClient(PerSourceAntivirus.Infrastructure.ThreatFeeds.ThreatFeedHttpClient.Name, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(60);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("PerSourceAntivirus/1.0");
        });
        services.AddHttpClient(PerSourceAntivirus.Infrastructure.Siem.SyslogCefExporter.HttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(15);
        });

        // Encrypt persourceav.db at rest via SQLCipher. The e_sqlcipher provider transparently
        // reads existing plaintext databases too, so this is safe to set unconditionally;
        // DatabaseEncryptionMigrator then converts any pre-existing plaintext file in place.
        SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_e_sqlcipher());

        var baseConnectionString = configuration.GetConnectionString("DefaultConnection")
            ?? "Data Source=persourceav.db";
        var dbKeyFile = Path.Combine(AppContext.BaseDirectory, "data", "db.key");
        var dbPassphrase = PerSourceAntivirus.Infrastructure.Persistence.DatabaseEncryptionKeyProvider.GetOrCreatePassphrase(dbKeyFile);

        var dbFilePathMatch = System.Text.RegularExpressions.Regex.Match(baseConnectionString, @"Data Source=([^;]+)");
        if (dbFilePathMatch.Success)
        {
            var dbFilePath = dbFilePathMatch.Groups[1].Value;
            if (!Path.IsPathRooted(dbFilePath)) dbFilePath = Path.Combine(AppContext.BaseDirectory, dbFilePath);
            PerSourceAntivirus.Infrastructure.Persistence.DatabaseEncryptionMigrator.EnsureEncrypted(dbFilePath, dbPassphrase);
        }

        var encryptedConnectionString = $"{baseConnectionString};Password={dbPassphrase}";
        services.AddDbContext<AppDbContext>(options =>
            options.UseSqlite(encryptedConnectionString));

        services.AddScoped<IScannedFileRepository, ScannedFileRepository>();
        services.AddScoped<INetworkConnectionEventRepository, NetworkConnectionEventRepository>();
        services.AddScoped<IDnsEventRepository, DnsEventRepository>();
        services.AddScoped<IProcessEventRepository, ProcessEventRepository>();
        services.AddScoped<IScheduledScanRepository, ScheduledScanRepository>();
        services.AddScoped<FileScanService>();

        services.AddSingleton<IFileHashCalculator, FileHashCalculator>();
        services.AddSingleton<IPeAnalyzer, PeAnalyzer>();
        services.AddSingleton<IScriptAnalyzer, ScriptAnalyzer>();
        services.AddSingleton<IFileMetadataAnalyzer, MetadataExtractorAnalyzer>();
        services.AddSingleton<IOfficeMacroAnalyzer, OfficeMacroAnalyzer>();
        services.AddSingleton<INetworkMonitor, SharpPcapNetworkMonitor>();
        services.AddSingleton<IFileSystemMonitor, FileSystemWatcherMonitor>();
        services.AddSingleton<IExclusionList>(sp => new ConfiguredExclusionList(configuration));

        var maxParallelism = int.TryParse(configuration["Scan:MaxParallelism"], out var mp) ? mp : 0;
        if (maxParallelism <= 0) maxParallelism = Environment.ProcessorCount;
        services.AddSingleton(new ScanSettings(maxParallelism));

        // YARA rules directory
        var rulesDir = configuration["Yara:RulesDirectory"] ?? "data/yara-rules";
        if (!Path.IsPathRooted(rulesDir))
            rulesDir = Path.Combine(AppContext.BaseDirectory, rulesDir);

        var yaraScanner = new YaraScanner(rulesDir);
        services.AddSingleton<IYaraScanner>(yaraScanner);

        // YARA rules auto-update URLs
        var updateUrls = configuration.GetSection("Yara:UpdateUrls")
            .GetChildren()
            .Select(c => c.Value ?? string.Empty)
            .Where(v => v.Length > 0)
            .ToList();
        services.AddSingleton<IYaraRulesUpdater>(_ => new HttpYaraRulesUpdater(yaraScanner, rulesDir, updateUrls));

        // IP blocklist
        var blocklistFile = configuration["Network:IpBlocklistFile"] ?? "data/ip-blocklist.txt";
        if (!Path.IsPathRooted(blocklistFile))
            blocklistFile = Path.Combine(AppContext.BaseDirectory, blocklistFile);

        var blocklistProvider = new StaticBlocklistProvider(blocklistFile);
        services.AddSingleton<IBlocklistProvider>(blocklistProvider);

        var updateUrl = configuration["Network:BlocklistUpdateUrl"]
            ?? "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
        services.AddSingleton<IBlocklistUpdater>(
            _ => new HttpBlocklistUpdater(blocklistProvider, blocklistFile, updateUrl));

        // Domain blocklist for DNS monitoring
        var domainBlocklistFile = configuration["Network:DomainBlocklistFile"] ?? "data/domain-blocklist.txt";
        if (!Path.IsPathRooted(domainBlocklistFile))
            domainBlocklistFile = Path.Combine(AppContext.BaseDirectory, domainBlocklistFile);

        var domainBlocklist = new StaticDomainBlocklist(domainBlocklistFile);
        services.AddSingleton<IDomainBlocklist>(domainBlocklist);
        services.AddSingleton<IDnsMonitor, SharpPcapDnsMonitor>();

        // Process monitor (Windows WMI) + snapshot provider for check-running
        services.AddSingleton<IProcessMonitor, WmiProcessMonitor>();
        services.AddSingleton<IRunningProcessProvider, SystemRunningProcessProvider>();

        // Quarantine
        var quarantineDir = configuration["Quarantine:Directory"] ?? "quarantine";
        if (!Path.IsPathRooted(quarantineDir))
            quarantineDir = Path.Combine(AppContext.BaseDirectory, quarantineDir);
        services.AddSingleton<IQuarantineService>(_ => new FileQuarantineService(quarantineDir));

        // Hash reputation
        var vtApiKey = configuration["Reputation:VirusTotalApiKey"] ?? string.Empty;
        var localHashFile = configuration["Reputation:LocalHashBlocklistFile"] ?? "data/known-malicious-hashes.txt";
        if (!Path.IsPathRooted(localHashFile))
            localHashFile = Path.Combine(AppContext.BaseDirectory, localHashFile);

        var localReputation = new LocalHashReputationService(localHashFile);
        var vtReputation = new VirusTotalHashReputationService(vtApiKey);
        services.AddSingleton<IHashReputationService>(_ => new CompositeHashReputationService(localReputation, vtReputation));

        // Threat intelligence feed updaters (Group 3)
        services.AddSingleton<IThreatFeedUpdater>(sp => new FeodoTrackerUpdater(
            blocklistProvider, blocklistFile, sp.GetRequiredService<IHttpClientFactory>()));
        services.AddSingleton<IThreatFeedUpdater>(sp => new MalwareBazaarUpdater(
            localReputation, localHashFile, sp.GetRequiredService<IHttpClientFactory>()));
        services.AddSingleton<IThreatFeedUpdater>(sp => new UrlhausUpdater(
            domainBlocklist, domainBlocklistFile, sp.GetRequiredService<IHttpClientFactory>()));

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
        var modelsDir = Path.Combine(AppContext.BaseDirectory, "data", "models");
        Directory.CreateDirectory(modelsDir);
        services.AddSingleton<IPeMlClassifier>(new PerSourceAntivirus.Infrastructure.Pe.OnnxPeMlClassifier(modelsDir));
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

        // Phase 13 â€” new detection engines
        services.AddSingleton<ICpuEmulator, X86CpuEmulator>();
        services.AddSingleton<IPackerDetector, PackerDetector>();
        services.AddSingleton<IAmsiProvider, AmsiProviderService>();
        services.AddSingleton<IWscRegistration, WscRegistrationService>();
        services.AddSingleton<ILolBinDetector, LolBinDetector>();
        services.AddScoped<ILolBinAlertRepository, LolBinAlertRepository>();
        services.AddSingleton<IFilelessDetector, FilelessMalwareDetector>();
        services.AddScoped<IFilelessAlertRepository, FilelessAlertRepository>();
        services.AddSingleton<IDgaDetector, DgaDetector>();
        services.AddScoped<IDgaAlertRepository, DgaAlertRepository>();
        services.AddSingleton<IAdsScanner, AdsScanner>();
        services.AddSingleton<IArchiveScanner, SharpCompressArchiveScanner>();
        services.AddSingleton<IPdfScanner, PdfPigScanner>();
        services.AddSingleton<IEmailScanner, MimeKitEmailScanner>();
        services.AddSingleton<ISteganographyDetector, LsbSteganographyDetector>();

        // Phase 14 â€” Advanced exploit prevention
        services.AddSingleton<IProcessHollowingDetector, ProcessHollowingDetector>();
        services.AddScoped<IProcessHollowingAlertRepository, ProcessHollowingAlertRepository>();
        services.AddSingleton<IProcessDoppelgangingDetector, ProcessDoppelgangingDetector>();
        services.AddScoped<IProcessDoppelgangingAlertRepository, ProcessDoppelgangingAlertRepository>();
        services.AddSingleton<IReflectiveDllInjectionDetector, ReflectiveDllInjectionDetector>();
        services.AddScoped<IReflectiveDllInjectionAlertRepository, ReflectiveDllInjectionAlertRepository>();
        services.AddSingleton<IAtomBombingDetector, AtomBombingDetector>();
        services.AddScoped<IAtomBombingAlertRepository, AtomBombingAlertRepository>();
        services.AddSingleton<IHeavensGateDetector, HeavensGateDetector>();
        services.AddScoped<IHeavensGateAlertRepository, HeavensGateAlertRepository>();
        services.AddSingleton<INtdllUnhookingDetector, NtdllUnhookingDetector>();
        services.AddScoped<INtdllUnhookingAlertRepository, NtdllUnhookingAlertRepository>();
        services.AddSingleton<IDirectSyscallDetector, DirectSyscallDetector>();
        services.AddScoped<IDirectSyscallAlertRepository, DirectSyscallAlertRepository>();
        services.AddSingleton<IHeapSprayDetector, HeapSprayDetector>();
        services.AddScoped<IHeapSprayAlertRepository, HeapSprayAlertRepository>();
        services.AddSingleton<IStackPivotDetector, StackPivotDetector>();
        services.AddScoped<IStackPivotAlertRepository, StackPivotAlertRepository>();
        services.AddSingleton<IProcessGhostingDetector, ProcessGhostingDetector>();
        services.AddScoped<IProcessGhostingAlertRepository, ProcessGhostingAlertRepository>();
        services.AddSingleton<IModuleStompingDetector, ModuleStompingDetector>();
        services.AddScoped<IModuleStompingAlertRepository, ModuleStompingAlertRepository>();
        services.AddSingleton<ITransactedHollowingDetector, TransactedHollowingDetector>();
        services.AddScoped<ITransactedHollowingAlertRepository, TransactedHollowingAlertRepository>();

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

        // Phase 19 — DLL search-order hijacking
        services.AddSingleton<IDllHijackDetector, DllHijackDetector>();
        services.AddScoped<IDllHijackAlertRepository, DllHijackAlertRepository>();

        // Phase 19 — Cryptojacking (CPU + mining-pool port correlation)
        services.AddSingleton<ICryptojackingDetector, CryptojackingDetector>();
        services.AddScoped<ICryptojackingAlertRepository, CryptojackingAlertRepository>();

        // Phase 19 — Authenticode verification + unsigned/untrusted binary detection
        services.AddSingleton<IAuthenticodeVerifier, AuthenticodeVerifier>();
        services.AddSingleton<IUnsignedBinaryDetector, UnsignedBinaryDetector>();
        services.AddScoped<IUnsignedBinaryAlertRepository, UnsignedBinaryAlertRepository>();

        // Phase 19 — Custom signature engine (hash + wildcard), complementary to YARA
        var customSignaturesFile = configuration["Signatures:CustomSignaturesFile"] ?? "data/custom-signatures.txt";
        if (!Path.IsPathRooted(customSignaturesFile))
            customSignaturesFile = Path.Combine(AppContext.BaseDirectory, customSignaturesFile);
        services.AddSingleton<ICustomSignatureEngine>(_ => new CustomSignatureEngine(customSignaturesFile));
        services.AddScoped<ICustomSignatureMatchRepository, CustomSignatureMatchRepository>();

        // Phase 19 — Certificate trust list (whitelist/blacklist by Authenticode thumbprint)
        services.AddScoped<ICertificateTrustEntryRepository, CertificateTrustEntryRepository>();
        services.AddSingleton<ICertificateTrustListService, CertificateTrustListService>();
        services.AddSingleton<ICertificateTrustDetector, CertificateTrustDetector>();
        services.AddScoped<ICertificateTrustAlertRepository, CertificateTrustAlertRepository>();

        // Phase 20 — Network: hosts-file DNS filtering, per-process firewall, DNS tunneling, GeoIP
        var domainBlocklistFileForHosts = configuration["Network:DomainBlocklistFile"] ?? "data/domain-blocklist.txt";
        if (!Path.IsPathRooted(domainBlocklistFileForHosts))
            domainBlocklistFileForHosts = Path.Combine(AppContext.BaseDirectory, domainBlocklistFileForHosts);
        services.AddSingleton<IHostsFileBlocklistService>(_ => new HostsFileBlocklistService(domainBlocklistFileForHosts));

        services.AddScoped<IProcessFirewallRuleRepository, ProcessFirewallRuleRepository>();
        services.AddSingleton<IProcessFirewallService, ProcessFirewallService>();

        services.AddSingleton<IDnsTunnelingDetector, DnsTunnelingDetector>();
        services.AddScoped<IDnsTunnelingAlertRepository, DnsTunnelingAlertRepository>();

        var geoIpDatabaseFile = configuration["GeoIp:DatabaseFile"] ?? "data/geoip-country-ranges.csv";
        if (!Path.IsPathRooted(geoIpDatabaseFile))
            geoIpDatabaseFile = Path.Combine(AppContext.BaseDirectory, geoIpDatabaseFile);
        var blockedCountries = configuration.GetSection("GeoIp:BlockedCountries")
            .GetChildren().Select(c => c.Value ?? string.Empty).Where(v => v.Length > 0).ToList();
        services.AddSingleton<IGeoIpBlockingService>(_ => new GeoIpBlockingService(geoIpDatabaseFile, blockedCountries));
        services.AddSingleton<IGeoIpEnforcementDetector, GeoIpEnforcementDetector>();
        services.AddScoped<IGeoIpBlockAlertRepository, GeoIpBlockAlertRepository>();

        // Phase 20 — GUI/UX backend: gamer mode + scheduled reports
        services.AddSingleton<IFullScreenDetector, PerSourceAntivirus.Infrastructure.SystemIntegration.FullScreenDetector>();
        var reportsDir = Path.Combine(AppContext.BaseDirectory, "data", "reports");
        services.AddHostedService(sp => new PerSourceAntivirus.Infrastructure.Reporting.ThreatReportSchedulerService(
            sp.GetRequiredService<IServiceScopeFactory>(), reportsDir));

        // Phase 20 — OS integration: Explorer context menu, Secure Boot, USB device control
        services.AddSingleton<IExplorerContextMenuInstaller, PerSourceAntivirus.Infrastructure.SystemIntegration.ExplorerContextMenuInstaller>();
        services.AddSingleton<ISecureBootVerifier, PerSourceAntivirus.Infrastructure.Uefi.SecureBootVerifier>();
        services.AddScoped<ISecureBootSnapshotRepository, PerSourceAntivirus.Infrastructure.Uefi.SecureBootSnapshotRepository>();

        var usbAllowlistFile = configuration["UsbControl:AllowlistFile"] ?? "data/usb-allowlist.txt";
        if (!Path.IsPathRooted(usbAllowlistFile))
            usbAllowlistFile = Path.Combine(AppContext.BaseDirectory, usbAllowlistFile);
        services.AddSingleton<IUsbDeviceControlService>(sp => new PerSourceAntivirus.Infrastructure.SystemIntegration.UsbDeviceControlService(
            sp.GetRequiredService<IServiceScopeFactory>(), usbAllowlistFile));
        services.AddScoped<IUsbDeviceEventRepository, PerSourceAntivirus.Infrastructure.SystemIntegration.UsbDeviceEventRepository>();

        // Phase 20 — ML: incremental active-learning classifier
        var activeLearningWeightsFile = Path.Combine(AppContext.BaseDirectory, "data", "models", "active-learning-weights.json");
        services.AddSingleton<IActiveLearningService>(sp => new PerSourceAntivirus.Infrastructure.Pe.ActiveLearningService(
            sp.GetRequiredService<IServiceScopeFactory>(), activeLearningWeightsFile));
        services.AddScoped<IActiveLearningSampleRepository, PerSourceAntivirus.Infrastructure.Pe.ActiveLearningSampleRepository>();

        // Phase 20 — Observability: Prometheus metrics, multi-agent CEF ingestion, audit hash chain
        services.AddSingleton<IMetricsExporter, PerSourceAntivirus.Infrastructure.Reporting.PrometheusMetricsExporter>();
        services.AddSingleton<ISyslogCefIngestionService, PerSourceAntivirus.Infrastructure.Siem.SyslogCefIngestionService>();
        services.AddScoped<IRemoteAgentEventRepository, PerSourceAntivirus.Infrastructure.Siem.RemoteAgentEventRepository>();
        services.AddScoped<IAuditLogChainService, PerSourceAntivirus.Infrastructure.Security.AuditLogChainService>();

        // Phase 21 — Threat intel: additional open feeds (OTX / ThreatFox / PhishTank)
        var otxApiKey = configuration["ThreatIntel:OtxApiKey"] ?? string.Empty;
        var threatIntelCacheDir = Path.Combine(AppContext.BaseDirectory, "data", "threat-intel-cache");
        services.AddSingleton<IThreatFeedUpdater>(sp => new PerSourceAntivirus.Infrastructure.ThreatFeeds.ThreatFoxUpdater(
            sp.GetRequiredService<IServiceScopeFactory>(),
            blocklistProvider, blocklistFile, domainBlocklist, domainBlocklistFile,
            Path.Combine(threatIntelCacheDir, "threatfox.cache.json"),
            sp.GetRequiredService<IHttpClientFactory>()));
        services.AddSingleton<IThreatFeedUpdater>(sp => new PerSourceAntivirus.Infrastructure.ThreatFeeds.OtxThreatFeedUpdater(
            otxApiKey, sp.GetRequiredService<IServiceScopeFactory>(),
            blocklistProvider, blocklistFile, domainBlocklist, domainBlocklistFile,
            Path.Combine(threatIntelCacheDir, "otx.cache.json"),
            sp.GetRequiredService<IHttpClientFactory>()));
        services.AddSingleton<IThreatFeedUpdater>(sp => new PerSourceAntivirus.Infrastructure.ThreatFeeds.PhishTankUpdater(
            sp.GetRequiredService<IServiceScopeFactory>(), domainBlocklist, domainBlocklistFile,
            Path.Combine(threatIntelCacheDir, "phishtank.cache.json"),
            sp.GetRequiredService<IHttpClientFactory>()));

        // Phase 21 — Threat intel: aggregated IP/domain reputation scoring + STIX export
        services.AddSingleton<IIpDomainReputationScoringService, PerSourceAntivirus.Infrastructure.Reputation.IpDomainReputationScoringService>();
        services.AddScoped<IStixIocExporter, PerSourceAntivirus.Infrastructure.ThreatIntel.StixIocExporter>();

        // Phase 21 — Response/remediation: kill-switch, sample submission, playbooks, System Restore
        services.AddSingleton<IHostIsolationService, PerSourceAntivirus.Infrastructure.Network.HostIsolationService>();
        services.AddScoped<IHostIsolationEventRepository, PerSourceAntivirus.Infrastructure.Network.HostIsolationEventRepository>();

        var samplePackageDir = Path.Combine(AppContext.BaseDirectory, "data", "sample-submissions");
        services.AddSingleton<ISampleSubmissionService>(sp => new PerSourceAntivirus.Infrastructure.Files.SampleSubmissionService(
            sp.GetRequiredService<IServiceScopeFactory>(), sp.GetRequiredService<IHttpClientFactory>(), samplePackageDir));
        services.AddScoped<ISampleSubmissionRepository, PerSourceAntivirus.Infrastructure.Files.SampleSubmissionRepository>();

        services.AddScoped<IResponsePlaybookRuleRepository, PerSourceAntivirus.Infrastructure.Response.ResponsePlaybookRuleRepository>();
        services.AddScoped<IPlaybookExecutionLogRepository, PerSourceAntivirus.Infrastructure.Response.PlaybookExecutionLogRepository>();
        services.AddSingleton<IResponsePlaybookEngine>(sp => new PerSourceAntivirus.Infrastructure.Response.ResponsePlaybookEngine(
            sp.GetRequiredService<IServiceScopeFactory>(), quarantineDir));

        services.AddSingleton<ISystemRestoreService, PerSourceAntivirus.Infrastructure.SystemIntegration.SystemRestoreService>();

        // [ADR-001] Detector health registry. Singleton so counters accumulate across the whole
        // process lifetime; consumed by the detectors, the hosted service and /metrics.
        services.AddSingleton<IDetectorDiagnostics, PerSourceAntivirus.Infrastructure.Diagnostics.DetectorDiagnostics>();

        // [AUDIT FIX — CRITICAL] Composition root for the 42 real-time detectors that were
        // registered but never started (see RealtimeProtectionHostedService for details).
        // Gated by the same RealtimeProtection:Enabled flag the GUI Settings page already
        // exposes — previously read by the GUI but never actually wired to anything.
        services.AddHostedService<RealtimeProtectionHostedService>();

        return services;
    }
}


