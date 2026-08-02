using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public partial class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<ScannedFile> ScannedFiles => Set<ScannedFile>();
    public DbSet<YaraMatch> YaraMatches => Set<YaraMatch>();
    public DbSet<PeAnalysisResult> PeAnalysisResults => Set<PeAnalysisResult>();
    public DbSet<PeSection> PeSections => Set<PeSection>();
    public DbSet<NetworkConnectionEvent> NetworkConnectionEvents => Set<NetworkConnectionEvent>();
    public DbSet<ScriptAnalysisResult> ScriptAnalysisResults => Set<ScriptAnalysisResult>();
    public DbSet<HashReputationResult> HashReputationResults => Set<HashReputationResult>();
    public DbSet<DnsQueryEvent> DnsQueryEvents => Set<DnsQueryEvent>();
    public DbSet<ProcessEvent> ProcessEvents => Set<ProcessEvent>();
    public DbSet<ScheduledScan> ScheduledScans => Set<ScheduledScan>();
    public DbSet<FileMetadataAnalysisResult> FileMetadataResults => Set<FileMetadataAnalysisResult>();
    public DbSet<OfficeMacroAnalysisResult> OfficeMacroResults => Set<OfficeMacroAnalysisResult>();
    public DbSet<MbrSnapshot> MbrSnapshots => Set<MbrSnapshot>();
    public DbSet<HoneypotFile> HoneypotFiles => Set<HoneypotFile>();
    public DbSet<RansomwareAlert> RansomwareAlerts => Set<RansomwareAlert>();
    public DbSet<PeMlPrediction> PeMlPredictions => Set<PeMlPrediction>();
    public DbSet<WfpBlock> WfpBlocks => Set<WfpBlock>();
    public DbSet<RootkitFinding> RootkitFindings => Set<RootkitFinding>();
    public DbSet<ExploitFinding> ExploitFindings => Set<ExploitFinding>();
    public DbSet<UefiFinding> UefiFindings => Set<UefiFinding>();
    public DbSet<WmiPersistenceAlert> WmiPersistenceAlerts => Set<WmiPersistenceAlert>();
    public DbSet<ComHijackAlert> ComHijackAlerts => Set<ComHijackAlert>();
    public DbSet<TlsInspectionEvent> TlsInspectionEvents => Set<TlsInspectionEvent>();

    // Phase 13 — new detection engines
    public DbSet<EmulationResult> EmulationResults => Set<EmulationResult>();
    public DbSet<UnpackingResult> UnpackingResults => Set<UnpackingResult>();
    public DbSet<AmsiScanEvent> AmsiScanEvents => Set<AmsiScanEvent>();
    public DbSet<LolBinAlert> LolBinAlerts => Set<LolBinAlert>();
    public DbSet<FilelessAlert> FilelessAlerts => Set<FilelessAlert>();
    public DbSet<DgaAlert> DgaAlerts => Set<DgaAlert>();
    public DbSet<AdsStreamInfo> AdsStreamInfos => Set<AdsStreamInfo>();
    public DbSet<ArchiveEntryResult> ArchiveEntryResults => Set<ArchiveEntryResult>();
    public DbSet<PdfScanResult> PdfScanResults => Set<PdfScanResult>();
    public DbSet<EmailScanResult> EmailScanResults => Set<EmailScanResult>();
    public DbSet<SteganographyAlert> SteganographyAlerts => Set<SteganographyAlert>();

    // Phase 15 — Network security + kernel protection
    public DbSet<NetworkIntrusionAlert> NetworkIntrusionAlerts => Set<NetworkIntrusionAlert>();
    public DbSet<ArpSpoofingAlert> ArpSpoofingAlerts => Set<ArpSpoofingAlert>();
    public DbSet<LlmnrPoisoningAlert> LlmnrPoisoningAlerts => Set<LlmnrPoisoningAlert>();
    public DbSet<KeyloggerDetectionAlert> KeyloggerDetectionAlerts => Set<KeyloggerDetectionAlert>();
    public DbSet<SafeFolderViolationAlert> SafeFolderViolationAlerts => Set<SafeFolderViolationAlert>();

    // Phase 16 — Network detection (items 36–40)
    public DbSet<PortScanAlert> PortScanAlerts => Set<PortScanAlert>();
    public DbSet<SmbLateralMovementAlert> SmbLateralMovementAlerts => Set<SmbLateralMovementAlert>();
    public DbSet<TlsCertAlert> TlsCertAlerts => Set<TlsCertAlert>();
    public DbSet<BeaconingAnalysis> BeaconingAnalyses => Set<BeaconingAnalysis>();
    public DbSet<WpadAbuseAlert> WpadAbuseAlerts => Set<WpadAbuseAlert>();

    // Phase 16 — Ransomware prevention (items 41–43)
    public DbSet<VssSnapshotEvent> VssSnapshotEvents => Set<VssSnapshotEvent>();
    public DbSet<ScreenLockerAlert> ScreenLockerAlerts => Set<ScreenLockerAlert>();
    public DbSet<MbrWriteAttemptAlert> MbrWriteAttemptAlerts => Set<MbrWriteAttemptAlert>();

    // Phase 16 — Privacy (items 44–48)
    public DbSet<ClipboardHijackAlert> ClipboardHijackAlerts => Set<ClipboardHijackAlert>();
    public DbSet<WebcamAccessEvent> WebcamAccessEvents => Set<WebcamAccessEvent>();
    public DbSet<MicrophoneAccessEvent> MicrophoneAccessEvents => Set<MicrophoneAccessEvent>();
    public DbSet<ScreenCaptureAlert> ScreenCaptureAlerts => Set<ScreenCaptureAlert>();

    // Phase 16 — Scanners + audit (items 49–55)
    public DbSet<SensitiveDataFinding> SensitiveDataFindings => Set<SensitiveDataFinding>();
    public DbSet<VulnerableSoftwareAlert> VulnerableSoftwareAlerts => Set<VulnerableSoftwareAlert>();
    public DbSet<SecurityPostureIssue> SecurityPostureIssues => Set<SecurityPostureIssue>();
    public DbSet<AutostartEntry> AutostartEntries => Set<AutostartEntry>();
    public DbSet<ServiceAuditFinding> ServiceAuditFindings => Set<ServiceAuditFinding>();
    public DbSet<UserAccountAuditFinding> UserAccountAuditFindings => Set<UserAccountAuditFinding>();
    public DbSet<OpenPortInfo> OpenPortInfos => Set<OpenPortInfo>();

    // Phase 17 — EDR event history (items 56–58)
    public DbSet<ProcessCreationEvent> ProcessCreationEvents => Set<ProcessCreationEvent>();
    public DbSet<FileActivityEvent> FileActivityEvents => Set<FileActivityEvent>();
    public DbSet<RegistryActivityEvent> RegistryActivityEvents => Set<RegistryActivityEvent>();

    // Phase 17 — Threat intelligence (items 59–62)
    public DbSet<MitreAttackMapping> MitreAttackMappings => Set<MitreAttackMapping>();
    public DbSet<CustomIoc> CustomIocs => Set<CustomIoc>();
    public DbSet<StixFeedSource> StixFeedSources => Set<StixFeedSource>();
    public DbSet<StixIoc> StixIocs => Set<StixIoc>();
    public DbSet<AlertTriage> AlertTriages => Set<AlertTriage>();
    public DbSet<Incident> Incidents => Set<Incident>();

    // Phase 17 — Application control + sandboxing (items 63–66)
    public DbSet<AppWhitelistEntry> AppWhitelistEntries => Set<AppWhitelistEntry>();
    public DbSet<PuaAlert> PuaAlerts => Set<PuaAlert>();
    public DbSet<ScriptSandboxResult> ScriptSandboxResults => Set<ScriptSandboxResult>();

    // Phase 17 — Browser protection (items 67–69)
    public DbSet<BrowserExtensionFinding> BrowserExtensionFindings => Set<BrowserExtensionFinding>();
    public DbSet<BrowserCredentialAccessAlert> BrowserCredentialAccessAlerts => Set<BrowserCredentialAccessAlert>();

    // Phase 17 — Process mitigation + security enforcement (items 70–74)
    public DbSet<CfgViolationAlert> CfgViolationAlerts => Set<CfgViolationAlert>();
    public DbSet<AmsiBypassAlert> AmsiBypassAlerts => Set<AmsiBypassAlert>();

    // Phase 18 — Notifications + scan profiles (items 80, 84)
    public DbSet<NotificationRecord> NotificationRecords => Set<NotificationRecord>();
    public DbSet<ScanProfile> ScanProfiles => Set<ScanProfile>();

    // Phase 18 — Behavioral analysis (items 75–78)
    public DbSet<ApiCallSequenceAlert> ApiCallSequenceAlerts => Set<ApiCallSequenceAlert>();
    public DbSet<ParentChildAnomalyAlert> ParentChildAnomalyAlerts => Set<ParentChildAnomalyAlert>();
    public DbSet<ProcessCommandLineAlert> ProcessCommandLineAlerts => Set<ProcessCommandLineAlert>();
    public DbSet<NetworkBehaviorProfile> NetworkBehaviorProfiles => Set<NetworkBehaviorProfile>();
    public DbSet<NetworkBehaviorAlert> NetworkBehaviorAlerts => Set<NetworkBehaviorAlert>();

    // Phase 18 — Reporting + forensics + security (items 87, 91–100)
    public DbSet<ThreatReport> ThreatReports => Set<ThreatReport>();
    public DbSet<MemoryDumpResult> MemoryDumpResults => Set<MemoryDumpResult>();
    public DbSet<FirmwareVariableSnapshot> FirmwareVariableSnapshots => Set<FirmwareVariableSnapshot>();
    public DbSet<HypervisorDetectionResult> HypervisorDetectionResults => Set<HypervisorDetectionResult>();
    public DbSet<KernelPatchGuardAlert> KernelPatchGuardAlerts => Set<KernelPatchGuardAlert>();
    public DbSet<SupplyChainAlert> SupplyChainAlerts => Set<SupplyChainAlert>();

    // Phase 14 — Advanced exploit prevention
    public DbSet<ProcessHollowingAlert> ProcessHollowingAlerts => Set<ProcessHollowingAlert>();
    public DbSet<ProcessDoppelgangingAlert> ProcessDoppelgangingAlerts => Set<ProcessDoppelgangingAlert>();
    public DbSet<ReflectiveDllInjectionAlert> ReflectiveDllInjectionAlerts => Set<ReflectiveDllInjectionAlert>();
    public DbSet<AtomBombingAlert> AtomBombingAlerts => Set<AtomBombingAlert>();
    public DbSet<HeavensGateAlert> HeavensGateAlerts => Set<HeavensGateAlert>();
    public DbSet<NtdllUnhookingAlert> NtdllUnhookingAlerts => Set<NtdllUnhookingAlert>();
    public DbSet<DirectSyscallAlert> DirectSyscallAlerts => Set<DirectSyscallAlert>();
    public DbSet<HeapSprayAlert> HeapSprayAlerts => Set<HeapSprayAlert>();
    public DbSet<StackPivotAlert> StackPivotAlerts => Set<StackPivotAlert>();
    public DbSet<ProcessGhostingAlert> ProcessGhostingAlerts => Set<ProcessGhostingAlert>();
    public DbSet<ModuleStompingAlert> ModuleStompingAlerts => Set<ModuleStompingAlert>();
    public DbSet<TransactedHollowingAlert> TransactedHollowingAlerts => Set<TransactedHollowingAlert>();

    // Phase 19 — DLL hijacking, cryptojacking, Authenticode/certificate trust, custom signatures
    public DbSet<DllHijackAlert> DllHijackAlerts => Set<DllHijackAlert>();
    public DbSet<CryptojackingAlert> CryptojackingAlerts => Set<CryptojackingAlert>();
    public DbSet<UnsignedBinaryAlert> UnsignedBinaryAlerts => Set<UnsignedBinaryAlert>();
    public DbSet<CustomSignatureMatch> CustomSignatureMatches => Set<CustomSignatureMatch>();
    public DbSet<CertificateTrustEntry> CertificateTrustEntries => Set<CertificateTrustEntry>();
    public DbSet<CertificateTrustAlert> CertificateTrustAlerts => Set<CertificateTrustAlert>();

    // Phase 20 — network/GUI/SO/ML/observability enhancements
    public DbSet<ProcessFirewallRule> ProcessFirewallRules => Set<ProcessFirewallRule>();
    public DbSet<DnsTunnelingAlert> DnsTunnelingAlerts => Set<DnsTunnelingAlert>();
    public DbSet<GeoIpBlockAlert> GeoIpBlockAlerts => Set<GeoIpBlockAlert>();
    public DbSet<SecureBootStatusSnapshot> SecureBootStatusSnapshots => Set<SecureBootStatusSnapshot>();
    public DbSet<UsbDeviceEvent> UsbDeviceEvents => Set<UsbDeviceEvent>();
    public DbSet<ActiveLearningSample> ActiveLearningSamples => Set<ActiveLearningSample>();
    public DbSet<RemoteAgentEvent> RemoteAgentEvents => Set<RemoteAgentEvent>();
    public DbSet<AuditLogChainEntry> AuditLogChainEntries => Set<AuditLogChainEntry>();

    // Phase 21 — threat intel scoring, response/remediation
    public DbSet<HostIsolationEvent> HostIsolationEvents => Set<HostIsolationEvent>();
    public DbSet<SampleSubmissionRecord> SampleSubmissionRecords => Set<SampleSubmissionRecord>();
    public DbSet<ResponsePlaybookRule> ResponsePlaybookRules => Set<ResponsePlaybookRule>();
    public DbSet<PlaybookExecutionLog> PlaybookExecutionLogs => Set<PlaybookExecutionLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // [ADR-002] Entity configuration lives in Configuration/*.cs partials, grouped by area.
        // The call order here matches the original single-method order exactly, so the model
        // EF builds is unchanged and no migration drift is introduced.
        ConfigureScanningEntities(modelBuilder);
        ConfigureDetectionEntities(modelBuilder);
        ConfigureResponseEntities(modelBuilder);
        ConfigureTelemetryEntities(modelBuilder);
    }
}
