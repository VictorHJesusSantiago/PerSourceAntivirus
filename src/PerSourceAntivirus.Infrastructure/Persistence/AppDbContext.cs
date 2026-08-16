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

    public DbSet<NetworkIntrusionAlert> NetworkIntrusionAlerts => Set<NetworkIntrusionAlert>();
    public DbSet<ArpSpoofingAlert> ArpSpoofingAlerts => Set<ArpSpoofingAlert>();
    public DbSet<LlmnrPoisoningAlert> LlmnrPoisoningAlerts => Set<LlmnrPoisoningAlert>();
    public DbSet<KeyloggerDetectionAlert> KeyloggerDetectionAlerts => Set<KeyloggerDetectionAlert>();
    public DbSet<SafeFolderViolationAlert> SafeFolderViolationAlerts => Set<SafeFolderViolationAlert>();

    public DbSet<PortScanAlert> PortScanAlerts => Set<PortScanAlert>();
    public DbSet<SmbLateralMovementAlert> SmbLateralMovementAlerts => Set<SmbLateralMovementAlert>();
    public DbSet<TlsCertAlert> TlsCertAlerts => Set<TlsCertAlert>();
    public DbSet<BeaconingAnalysis> BeaconingAnalyses => Set<BeaconingAnalysis>();
    public DbSet<WpadAbuseAlert> WpadAbuseAlerts => Set<WpadAbuseAlert>();

    public DbSet<VssSnapshotEvent> VssSnapshotEvents => Set<VssSnapshotEvent>();
    public DbSet<ScreenLockerAlert> ScreenLockerAlerts => Set<ScreenLockerAlert>();
    public DbSet<MbrWriteAttemptAlert> MbrWriteAttemptAlerts => Set<MbrWriteAttemptAlert>();

    public DbSet<ClipboardHijackAlert> ClipboardHijackAlerts => Set<ClipboardHijackAlert>();
    public DbSet<WebcamAccessEvent> WebcamAccessEvents => Set<WebcamAccessEvent>();
    public DbSet<MicrophoneAccessEvent> MicrophoneAccessEvents => Set<MicrophoneAccessEvent>();
    public DbSet<ScreenCaptureAlert> ScreenCaptureAlerts => Set<ScreenCaptureAlert>();

    public DbSet<SensitiveDataFinding> SensitiveDataFindings => Set<SensitiveDataFinding>();
    public DbSet<VulnerableSoftwareAlert> VulnerableSoftwareAlerts => Set<VulnerableSoftwareAlert>();
    public DbSet<SecurityPostureIssue> SecurityPostureIssues => Set<SecurityPostureIssue>();
    public DbSet<AutostartEntry> AutostartEntries => Set<AutostartEntry>();
    public DbSet<ServiceAuditFinding> ServiceAuditFindings => Set<ServiceAuditFinding>();
    public DbSet<UserAccountAuditFinding> UserAccountAuditFindings => Set<UserAccountAuditFinding>();
    public DbSet<OpenPortInfo> OpenPortInfos => Set<OpenPortInfo>();

    public DbSet<ProcessCreationEvent> ProcessCreationEvents => Set<ProcessCreationEvent>();
    public DbSet<FileActivityEvent> FileActivityEvents => Set<FileActivityEvent>();
    public DbSet<RegistryActivityEvent> RegistryActivityEvents => Set<RegistryActivityEvent>();

    public DbSet<MitreAttackMapping> MitreAttackMappings => Set<MitreAttackMapping>();
    public DbSet<CustomIoc> CustomIocs => Set<CustomIoc>();
    public DbSet<StixFeedSource> StixFeedSources => Set<StixFeedSource>();
    public DbSet<StixIoc> StixIocs => Set<StixIoc>();
    public DbSet<AlertTriage> AlertTriages => Set<AlertTriage>();
    public DbSet<Incident> Incidents => Set<Incident>();

    public DbSet<AppWhitelistEntry> AppWhitelistEntries => Set<AppWhitelistEntry>();
    public DbSet<PuaAlert> PuaAlerts => Set<PuaAlert>();
    public DbSet<ScriptSandboxResult> ScriptSandboxResults => Set<ScriptSandboxResult>();

    public DbSet<BrowserExtensionFinding> BrowserExtensionFindings => Set<BrowserExtensionFinding>();
    public DbSet<BrowserCredentialAccessAlert> BrowserCredentialAccessAlerts => Set<BrowserCredentialAccessAlert>();

    public DbSet<CfgViolationAlert> CfgViolationAlerts => Set<CfgViolationAlert>();
    public DbSet<AmsiBypassAlert> AmsiBypassAlerts => Set<AmsiBypassAlert>();

    public DbSet<NotificationRecord> NotificationRecords => Set<NotificationRecord>();
    public DbSet<ScanProfile> ScanProfiles => Set<ScanProfile>();

    public DbSet<ApiCallSequenceAlert> ApiCallSequenceAlerts => Set<ApiCallSequenceAlert>();
    public DbSet<ParentChildAnomalyAlert> ParentChildAnomalyAlerts => Set<ParentChildAnomalyAlert>();
    public DbSet<ProcessCommandLineAlert> ProcessCommandLineAlerts => Set<ProcessCommandLineAlert>();
    public DbSet<NetworkBehaviorProfile> NetworkBehaviorProfiles => Set<NetworkBehaviorProfile>();
    public DbSet<NetworkBehaviorAlert> NetworkBehaviorAlerts => Set<NetworkBehaviorAlert>();

    public DbSet<ThreatReport> ThreatReports => Set<ThreatReport>();
    public DbSet<MemoryDumpResult> MemoryDumpResults => Set<MemoryDumpResult>();
    public DbSet<FirmwareVariableSnapshot> FirmwareVariableSnapshots => Set<FirmwareVariableSnapshot>();
    public DbSet<HypervisorDetectionResult> HypervisorDetectionResults => Set<HypervisorDetectionResult>();
    public DbSet<KernelPatchGuardAlert> KernelPatchGuardAlerts => Set<KernelPatchGuardAlert>();
    public DbSet<SupplyChainAlert> SupplyChainAlerts => Set<SupplyChainAlert>();

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

    public DbSet<DllHijackAlert> DllHijackAlerts => Set<DllHijackAlert>();
    public DbSet<CryptojackingAlert> CryptojackingAlerts => Set<CryptojackingAlert>();
    public DbSet<UnsignedBinaryAlert> UnsignedBinaryAlerts => Set<UnsignedBinaryAlert>();
    public DbSet<CustomSignatureMatch> CustomSignatureMatches => Set<CustomSignatureMatch>();
    public DbSet<CertificateTrustEntry> CertificateTrustEntries => Set<CertificateTrustEntry>();
    public DbSet<CertificateTrustAlert> CertificateTrustAlerts => Set<CertificateTrustAlert>();

    public DbSet<ProcessFirewallRule> ProcessFirewallRules => Set<ProcessFirewallRule>();
    public DbSet<DnsTunnelingAlert> DnsTunnelingAlerts => Set<DnsTunnelingAlert>();
    public DbSet<GeoIpBlockAlert> GeoIpBlockAlerts => Set<GeoIpBlockAlert>();
    public DbSet<SecureBootStatusSnapshot> SecureBootStatusSnapshots => Set<SecureBootStatusSnapshot>();
    public DbSet<UsbDeviceEvent> UsbDeviceEvents => Set<UsbDeviceEvent>();
    public DbSet<ActiveLearningSample> ActiveLearningSamples => Set<ActiveLearningSample>();
    public DbSet<RemoteAgentEvent> RemoteAgentEvents => Set<RemoteAgentEvent>();
    public DbSet<AuditLogChainEntry> AuditLogChainEntries => Set<AuditLogChainEntry>();

    public DbSet<HostIsolationEvent> HostIsolationEvents => Set<HostIsolationEvent>();
    public DbSet<SampleSubmissionRecord> SampleSubmissionRecords => Set<SampleSubmissionRecord>();
    public DbSet<ResponsePlaybookRule> ResponsePlaybookRules => Set<ResponsePlaybookRule>();
    public DbSet<PlaybookExecutionLog> PlaybookExecutionLogs => Set<PlaybookExecutionLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ConfigureScanningEntities(modelBuilder);
        ConfigureDetectionEntities(modelBuilder);
        ConfigureResponseEntities(modelBuilder);
        ConfigureTelemetryEntities(modelBuilder);
    }
}
