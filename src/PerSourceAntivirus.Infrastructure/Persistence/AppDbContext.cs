using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
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

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ScannedFile>(builder =>
        {
            builder.HasKey(f => f.Id);
            builder.Property(f => f.FilePath).IsRequired();
            builder.Property(f => f.FileName).IsRequired();
            builder.Property(f => f.Sha256Hash).IsRequired().HasMaxLength(64);

            builder.HasMany(f => f.YaraMatches)
                .WithOne(m => m.ScannedFile)
                .HasForeignKey(m => m.ScannedFileId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(f => f.PeAnalysis)
                .WithOne(p => p.ScannedFile)
                .HasForeignKey<PeAnalysisResult>(p => p.ScannedFileId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(f => f.ScriptAnalysis)
                .WithOne(s => s.ScannedFile)
                .HasForeignKey<ScriptAnalysisResult>(s => s.ScannedFileId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(f => f.HashReputation)
                .WithOne(r => r.ScannedFile)
                .HasForeignKey<HashReputationResult>(r => r.ScannedFileId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(f => f.FileMetadata)
                .WithOne(m => m.ScannedFile)
                .HasForeignKey<FileMetadataAnalysisResult>(m => m.ScannedFileId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(f => f.OfficeMacro)
                .WithOne(m => m.ScannedFile)
                .HasForeignKey<OfficeMacroAnalysisResult>(m => m.ScannedFileId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<YaraMatch>(builder =>
        {
            builder.HasKey(m => m.Id);
            builder.Property(m => m.RuleIdentifier).IsRequired();
            builder.Property(m => m.Tags).IsRequired();
        });

        modelBuilder.Entity<PeAnalysisResult>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.SuspiciousImports).IsRequired();
            builder.Property(p => p.Anomalies).IsRequired();

            builder.HasMany(p => p.Sections)
                .WithOne(s => s.PeAnalysisResult)
                .HasForeignKey(s => s.PeAnalysisResultId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<PeSection>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.Name).IsRequired();
        });

        modelBuilder.Entity<NetworkConnectionEvent>(builder =>
        {
            builder.HasKey(e => e.Id);
            builder.Property(e => e.SourceAddress).IsRequired();
            builder.Property(e => e.DestinationAddress).IsRequired();
        });

        modelBuilder.Entity<ScriptAnalysisResult>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.SuspiciousPatterns).IsRequired();
        });

        modelBuilder.Entity<HashReputationResult>(builder =>
        {
            builder.HasKey(r => r.Id);
            builder.Property(r => r.Source).IsRequired();
        });

        modelBuilder.Entity<DnsQueryEvent>(builder =>
        {
            builder.HasKey(e => e.Id);
            builder.Property(e => e.QueryName).IsRequired();
            builder.Property(e => e.QueryType).IsRequired();
            builder.Property(e => e.SourceAddress).IsRequired();
        });

        modelBuilder.Entity<ProcessEvent>(builder =>
        {
            builder.HasKey(e => e.Id);
            builder.Property(e => e.ProcessName).IsRequired();
        });

        modelBuilder.Entity<ScheduledScan>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.Path).IsRequired();
        });

        modelBuilder.Entity<FileMetadataAnalysisResult>(builder =>
        {
            builder.HasKey(m => m.Id);
            builder.Property(m => m.Anomalies).IsRequired();
        });

        modelBuilder.Entity<OfficeMacroAnalysisResult>(builder =>
        {
            builder.HasKey(m => m.Id);
            builder.Property(m => m.SuspiciousPatterns).IsRequired();
        });

        modelBuilder.Entity<MbrSnapshot>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.Sha256Hash).IsRequired().HasMaxLength(64);
            builder.HasIndex(s => new { s.DriveIndex, s.IsBaseline });
        });

        modelBuilder.Entity<PeMlPrediction>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.FilePath).IsRequired();
            builder.Property(p => p.Classification).IsRequired();
            builder.Property(p => p.ModelVersion).IsRequired();
            builder.HasIndex(p => p.Classification);
        });

        modelBuilder.Entity<WfpBlock>(builder =>
        {
            builder.HasKey(b => b.Id);
            builder.Property(b => b.IpAddress).IsRequired();
            builder.HasIndex(b => new { b.IpAddress, b.IsActive });
        });

        modelBuilder.Entity<HoneypotFile>(builder =>
        {
            builder.HasKey(h => h.Id);
            builder.Property(h => h.FilePath).IsRequired();
            builder.Property(h => h.FileName).IsRequired();
            builder.Property(h => h.DecoyType).IsRequired();
        });

        modelBuilder.Entity<RansomwareAlert>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.FilePath).IsRequired();
            builder.Property(a => a.Detail).IsRequired();
            builder.HasIndex(a => a.DetectedAtUtc);
            builder.HasIndex(a => a.Severity);
        });

        modelBuilder.Entity<RootkitFinding>(builder =>
        {
            builder.HasKey(r => r.Id);
            builder.Property(r => r.Description).IsRequired();
            builder.Property(r => r.Severity).IsRequired();
            builder.HasIndex(r => r.DetectedAtUtc);
        });

        modelBuilder.Entity<ExploitFinding>(builder =>
        {
            builder.HasKey(e => e.Id);
            builder.Property(e => e.ProcessName).IsRequired();
            builder.Property(e => e.DetectedPatterns).IsRequired();
            builder.HasIndex(e => e.DetectedAtUtc);
        });

        modelBuilder.Entity<UefiFinding>(builder =>
        {
            builder.HasKey(u => u.Id);
            builder.Property(u => u.TableName).IsRequired();
            builder.Property(u => u.SignatureName).IsRequired();
            builder.Property(u => u.Description).IsRequired();
            builder.HasIndex(u => u.DetectedAtUtc);
        });

        modelBuilder.Entity<WmiPersistenceAlert>(builder =>
        {
            builder.HasKey(w => w.Id);
            builder.Property(w => w.FilterName).IsRequired();
            builder.Property(w => w.ConsumerName).IsRequired();
            builder.Property(w => w.Severity).IsRequired();
            builder.HasIndex(w => w.DetectedAtUtc);
        });

        modelBuilder.Entity<ComHijackAlert>(builder =>
        {
            builder.HasKey(c => c.Id);
            builder.Property(c => c.AlertType).IsRequired();
            builder.Property(c => c.ClsidOrPath).IsRequired();
            builder.Property(c => c.SuspiciousPath).IsRequired();
            builder.Property(c => c.Severity).IsRequired();
            builder.HasIndex(c => c.DetectedAtUtc);
        });

        modelBuilder.Entity<TlsInspectionEvent>(builder =>
        {
            builder.HasKey(t => t.Id);
            builder.Property(t => t.TargetHost).IsRequired();
            builder.Property(t => t.Method).IsRequired();
            builder.Property(t => t.RequestPath).IsRequired();
            builder.HasIndex(t => t.CapturedAtUtc);
            builder.HasIndex(t => t.IsSuspicious);
        });

        modelBuilder.Entity<EmulationResult>(builder =>
        {
            builder.HasKey(e => e.Id);
            builder.Property(e => e.FilePath).IsRequired();
            builder.Property(e => e.DetectedPatterns).IsRequired();
            builder.HasIndex(e => e.EmulatedAtUtc);
        });

        modelBuilder.Entity<UnpackingResult>(builder =>
        {
            builder.HasKey(u => u.Id);
            builder.Property(u => u.FilePath).IsRequired();
            builder.Property(u => u.DetectedPacker).IsRequired();
            builder.HasIndex(u => u.DetectedAtUtc);
        });

        modelBuilder.Entity<AmsiScanEvent>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.ContentName).IsRequired();
            builder.HasIndex(a => a.ScannedAtUtc);
        });

        modelBuilder.Entity<LolBinAlert>(builder =>
        {
            builder.HasKey(l => l.Id);
            builder.Property(l => l.ProcessName).IsRequired();
            builder.Property(l => l.Arguments).IsRequired();
            builder.Property(l => l.LolbinName).IsRequired();
            builder.Property(l => l.Description).IsRequired();
            builder.Property(l => l.MitreTechnique).IsRequired();
            builder.HasIndex(l => l.AlertedAtUtc);
            builder.HasIndex(l => l.Severity);
        });

        modelBuilder.Entity<FilelessAlert>(builder =>
        {
            builder.HasKey(f => f.Id);
            builder.Property(f => f.TechniqueType).IsRequired();
            builder.Property(f => f.Detail).IsRequired();
            builder.Property(f => f.ProcessName).IsRequired();
            builder.HasIndex(f => f.DetectedAtUtc);
        });

        modelBuilder.Entity<DgaAlert>(builder =>
        {
            builder.HasKey(d => d.Id);
            builder.Property(d => d.Hostname).IsRequired();
            builder.HasIndex(d => d.DetectedAtUtc);
            builder.HasIndex(d => d.IsDga);
        });

        modelBuilder.Entity<AdsStreamInfo>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.StreamName).IsRequired();
            builder.Property(a => a.Reason).IsRequired();
            builder.HasIndex(a => a.ScannedFileId);
        });

        modelBuilder.Entity<ArchiveEntryResult>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.EntryPath).IsRequired();
            builder.Property(a => a.DetectionReason).IsRequired();
            builder.HasIndex(a => a.ArchiveScannedFileId);
        });

        modelBuilder.Entity<PdfScanResult>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.MaliciousObjectTypes).IsRequired();
            builder.HasIndex(p => p.ScannedFileId);
        });

        modelBuilder.Entity<EmailScanResult>(builder =>
        {
            builder.HasKey(e => e.Id);
            builder.Property(e => e.SuspiciousAttachmentNames).IsRequired();
            builder.Property(e => e.PhishingIndicators).IsRequired();
            builder.HasIndex(e => e.ScannedFileId);
        });

        modelBuilder.Entity<SteganographyAlert>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.FilePath).IsRequired();
            builder.Property(s => s.SuspicionReasons).IsRequired();
            builder.HasIndex(s => s.DetectedAtUtc);
            builder.HasIndex(s => s.IsSuspicious);
        });

        modelBuilder.Entity<ProcessHollowingAlert>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.TargetProcessName).IsRequired();
            builder.Property(p => p.InjectorProcessName).IsRequired();
            builder.Property(p => p.DetectedSequence).IsRequired();
            builder.HasIndex(p => p.DetectedAtUtc);
            builder.HasIndex(p => p.Severity);
        });

        modelBuilder.Entity<ProcessDoppelgangingAlert>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.ProcessName).IsRequired();
            builder.Property(p => p.ReportedImagePath).IsRequired();
            builder.Property(p => p.SuspicionReason).IsRequired();
            builder.HasIndex(p => p.DetectedAtUtc);
        });

        modelBuilder.Entity<ReflectiveDllInjectionAlert>(builder =>
        {
            builder.HasKey(r => r.Id);
            builder.Property(r => r.TargetProcessName).IsRequired();
            builder.HasIndex(r => r.DetectedAtUtc);
            builder.HasIndex(r => r.TargetProcessId);
        });

        modelBuilder.Entity<AtomBombingAlert>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.SuspiciousAtomContent).IsRequired();
            builder.Property(a => a.SuspicionReason).IsRequired();
            builder.HasIndex(a => a.DetectedAtUtc);
        });

        modelBuilder.Entity<HeavensGateAlert>(builder =>
        {
            builder.HasKey(h => h.Id);
            builder.Property(h => h.ProcessName).IsRequired();
            builder.Property(h => h.PatternType).IsRequired();
            builder.Property(h => h.PatternBytes).IsRequired();
            builder.HasIndex(h => h.DetectedAtUtc);
        });

        modelBuilder.Entity<NtdllUnhookingAlert>(builder =>
        {
            builder.HasKey(n => n.Id);
            builder.Property(n => n.TargetProcessName).IsRequired();
            builder.Property(n => n.MappedPaths).IsRequired();
            builder.Property(n => n.SuspicionReason).IsRequired();
            builder.HasIndex(n => n.DetectedAtUtc);
        });

        modelBuilder.Entity<DirectSyscallAlert>(builder =>
        {
            builder.HasKey(d => d.Id);
            builder.Property(d => d.ProcessName).IsRequired();
            builder.Property(d => d.InstructionType).IsRequired();
            builder.Property(d => d.ContainingModulePath).IsRequired();
            builder.HasIndex(d => d.DetectedAtUtc);
        });

        modelBuilder.Entity<HeapSprayAlert>(builder =>
        {
            builder.HasKey(h => h.Id);
            builder.Property(h => h.ProcessName).IsRequired();
            builder.Property(h => h.SuspicionReason).IsRequired();
            builder.HasIndex(h => h.DetectedAtUtc);
            builder.HasIndex(h => h.ProcessId);
        });

        modelBuilder.Entity<StackPivotAlert>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.ProcessName).IsRequired();
            builder.Property(s => s.SuspicionReason).IsRequired();
            builder.HasIndex(s => s.DetectedAtUtc);
        });

        modelBuilder.Entity<ProcessGhostingAlert>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.ProcessName).IsRequired();
            builder.Property(p => p.ReportedImagePath).IsRequired();
            builder.Property(p => p.DetectionMethod).IsRequired();
            builder.HasIndex(p => p.DetectedAtUtc);
        });

        modelBuilder.Entity<ModuleStompingAlert>(builder =>
        {
            builder.HasKey(m => m.Id);
            builder.Property(m => m.ProcessName).IsRequired();
            builder.Property(m => m.ModulePath).IsRequired();
            builder.Property(m => m.ModuleName).IsRequired();
            builder.Property(m => m.OnDiskHash).IsRequired();
            builder.Property(m => m.InMemoryHash).IsRequired();
            builder.Property(m => m.SuspicionReason).IsRequired();
            builder.HasIndex(m => m.DetectedAtUtc);
        });

        modelBuilder.Entity<TransactedHollowingAlert>(builder =>
        {
            builder.HasKey(t => t.Id);
            builder.Property(t => t.ProcessName).IsRequired();
            builder.Property(t => t.SuspiciousModulePath).IsRequired();
            builder.Property(t => t.DetectionMethod).IsRequired();
            builder.HasIndex(t => t.DetectedAtUtc);
        });

        modelBuilder.Entity<NetworkIntrusionAlert>(builder =>
        {
            builder.HasKey(n => n.Id);
            builder.Property(n => n.SignatureName).IsRequired();
            builder.Property(n => n.SourceIp).IsRequired();
            builder.Property(n => n.DestinationIp).IsRequired();
            builder.Property(n => n.Protocol).IsRequired();
            builder.Property(n => n.MatchedPattern).IsRequired();
            builder.Property(n => n.Description).IsRequired();
            builder.HasIndex(n => n.DetectedAtUtc);
            builder.HasIndex(n => n.Severity);
        });

        modelBuilder.Entity<ArpSpoofingAlert>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.AttackerMac).IsRequired();
            builder.Property(a => a.VictimIp).IsRequired();
            builder.Property(a => a.DetectionReason).IsRequired();
            builder.HasIndex(a => a.DetectedAtUtc);
        });

        modelBuilder.Entity<LlmnrPoisoningAlert>(builder =>
        {
            builder.HasKey(l => l.Id);
            builder.Property(l => l.Protocol).IsRequired();
            builder.Property(l => l.QueryName).IsRequired();
            builder.Property(l => l.ResponderIp).IsRequired();
            builder.Property(l => l.DetectionReason).IsRequired();
            builder.HasIndex(l => l.DetectedAtUtc);
        });

        modelBuilder.Entity<KeyloggerDetectionAlert>(builder =>
        {
            builder.HasKey(k => k.Id);
            builder.Property(k => k.ProcessName).IsRequired();
            builder.Property(k => k.DetectionMethod).IsRequired();
            builder.Property(k => k.SuspiciousDetail).IsRequired();
            builder.Property(k => k.ModulePath).IsRequired();
            builder.HasIndex(k => k.DetectedAtUtc);
            builder.HasIndex(k => k.Severity);
        });

        modelBuilder.Entity<SafeFolderViolationAlert>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.ProcessName).IsRequired();
            builder.Property(s => s.ProtectedPath).IsRequired();
            builder.Property(s => s.AttemptedOperation).IsRequired();
            builder.HasIndex(s => s.DetectedAtUtc);
            builder.HasIndex(s => s.WasBlocked);
        });

        modelBuilder.Entity<PortScanAlert>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.SourceIp).IsRequired();
            builder.Property(p => p.TargetPorts).IsRequired();
            builder.Property(p => p.DetectionMethod).IsRequired();
            builder.HasIndex(p => p.DetectedAtUtc);
            builder.HasIndex(p => p.Severity);
        });

        modelBuilder.Entity<SmbLateralMovementAlert>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.SourceIp).IsRequired();
            builder.Property(s => s.TargetIp).IsRequired();
            builder.Property(s => s.DetectionReason).IsRequired();
            builder.HasIndex(s => s.DetectedAtUtc);
            builder.HasIndex(s => s.Severity);
        });

        modelBuilder.Entity<TlsCertAlert>(builder =>
        {
            builder.HasKey(t => t.Id);
            builder.Property(t => t.Hostname).IsRequired();
            builder.Property(t => t.SubjectCn).IsRequired();
            builder.Property(t => t.IssuerCn).IsRequired();
            builder.Property(t => t.ValidationError).IsRequired();
            builder.HasIndex(t => t.DetectedAtUtc);
            builder.HasIndex(t => t.Hostname);
        });

        modelBuilder.Entity<BeaconingAnalysis>(builder =>
        {
            builder.HasKey(b => b.Id);
            builder.Property(b => b.DestinationIp).IsRequired();
            builder.Property(b => b.ProcessName).IsRequired();
            builder.HasIndex(b => b.DetectedAtUtc);
            builder.HasIndex(b => b.BeaconingScore);
        });

        modelBuilder.Entity<WpadAbuseAlert>(builder =>
        {
            builder.HasKey(w => w.Id);
            builder.Property(w => w.QueryType).IsRequired();
            builder.Property(w => w.Hostname).IsRequired();
            builder.Property(w => w.DetectionReason).IsRequired();
            builder.HasIndex(w => w.DetectedAtUtc);
        });

        modelBuilder.Entity<VssSnapshotEvent>(builder =>
        {
            builder.HasKey(v => v.Id);
            builder.Property(v => v.FolderPath).IsRequired();
            builder.Property(v => v.TriggerReason).IsRequired();
            builder.HasIndex(v => v.CreatedAtUtc);
        });

        modelBuilder.Entity<ScreenLockerAlert>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.ProcessName).IsRequired();
            builder.Property(s => s.DetectionMethod).IsRequired();
            builder.HasIndex(s => s.DetectedAtUtc);
        });

        modelBuilder.Entity<MbrWriteAttemptAlert>(builder =>
        {
            builder.HasKey(m => m.Id);
            builder.Property(m => m.ProcessName).IsRequired();
            builder.Property(m => m.DetectionMethod).IsRequired();
            builder.HasIndex(m => m.DetectedAtUtc);
            builder.HasIndex(m => m.Severity);
        });

        modelBuilder.Entity<ClipboardHijackAlert>(builder =>
        {
            builder.HasKey(c => c.Id);
            builder.Property(c => c.ProcessName).IsRequired();
            builder.Property(c => c.AddressType).IsRequired();
            builder.HasIndex(c => c.DetectedAtUtc);
        });

        modelBuilder.Entity<WebcamAccessEvent>(builder =>
        {
            builder.HasKey(w => w.Id);
            builder.Property(w => w.ProcessName).IsRequired();
            builder.Property(w => w.DevicePath).IsRequired();
            builder.HasIndex(w => w.DetectedAtUtc);
        });

        modelBuilder.Entity<MicrophoneAccessEvent>(builder =>
        {
            builder.HasKey(m => m.Id);
            builder.Property(m => m.ProcessName).IsRequired();
            builder.Property(m => m.DevicePath).IsRequired();
            builder.HasIndex(m => m.DetectedAtUtc);
        });

        modelBuilder.Entity<ScreenCaptureAlert>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.ProcessName).IsRequired();
            builder.Property(s => s.CaptureMethod).IsRequired();
            builder.HasIndex(s => s.DetectedAtUtc);
        });

        modelBuilder.Entity<SensitiveDataFinding>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.FilePath).IsRequired();
            builder.Property(s => s.DataType).IsRequired();
            builder.Property(s => s.MatchSnippet).IsRequired();
            builder.HasIndex(s => s.FoundAtUtc);
            builder.HasIndex(s => s.DataType);
        });

        modelBuilder.Entity<VulnerableSoftwareAlert>(builder =>
        {
            builder.HasKey(v => v.Id);
            builder.Property(v => v.SoftwareName).IsRequired();
            builder.Property(v => v.CveId).IsRequired();
            builder.HasIndex(v => v.DetectedAtUtc);
            builder.HasIndex(v => v.CvssScore);
        });

        modelBuilder.Entity<SecurityPostureIssue>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.CheckName).IsRequired();
            builder.Property(s => s.Category).IsRequired();
            builder.HasIndex(s => s.CheckedAtUtc);
            builder.HasIndex(s => s.Severity);
        });

        modelBuilder.Entity<AutostartEntry>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.Location).IsRequired();
            builder.Property(a => a.EntryName).IsRequired();
            builder.Property(a => a.Command).IsRequired();
            builder.Property(a => a.Classification).IsRequired();
            builder.HasIndex(a => a.AuditedAtUtc);
            builder.HasIndex(a => a.IsSuspicious);
        });

        modelBuilder.Entity<ServiceAuditFinding>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.ServiceName).IsRequired();
            builder.Property(s => s.BinaryPath).IsRequired();
            builder.Property(s => s.FindingType).IsRequired();
            builder.HasIndex(s => s.AuditedAtUtc);
        });

        modelBuilder.Entity<UserAccountAuditFinding>(builder =>
        {
            builder.HasKey(u => u.Id);
            builder.Property(u => u.AccountName).IsRequired();
            builder.Property(u => u.Issue).IsRequired();
            builder.Property(u => u.Classification).IsRequired();
            builder.HasIndex(u => u.AuditedAtUtc);
        });

        modelBuilder.Entity<OpenPortInfo>(builder =>
        {
            builder.HasKey(o => o.Id);
            builder.Property(o => o.Protocol).IsRequired();
            builder.Property(o => o.State).IsRequired();
            builder.Property(o => o.ProcessName).IsRequired();
            builder.HasIndex(o => o.ScannedAtUtc);
            builder.HasIndex(o => o.LocalPort);
        });

        modelBuilder.Entity<ProcessCreationEvent>(builder =>
        {
            builder.HasKey(e => e.Id);
            builder.Property(e => e.ImagePath).IsRequired();
            builder.Property(e => e.FileName).IsRequired();
            builder.Property(e => e.CommandLine).IsRequired();
            builder.Property(e => e.Sha256Hash).IsRequired().HasMaxLength(64);
            builder.Property(e => e.UserName).IsRequired();
            builder.Property(e => e.IntegrityLevel).IsRequired();
            builder.HasIndex(e => e.CreatedAtUtc);
            builder.HasIndex(e => e.ProcessId);
            builder.HasIndex(e => e.IsSuspicious);
        });

        modelBuilder.Entity<FileActivityEvent>(builder =>
        {
            builder.HasKey(e => e.Id);
            builder.Property(e => e.ProcessName).IsRequired();
            builder.Property(e => e.FilePath).IsRequired();
            builder.Property(e => e.FileName).IsRequired();
            builder.Property(e => e.Operation).IsRequired();
            builder.HasIndex(e => e.OccurredAtUtc);
            builder.HasIndex(e => e.ProcessId);
            builder.HasIndex(e => e.IsSuspicious);
        });

        modelBuilder.Entity<RegistryActivityEvent>(builder =>
        {
            builder.HasKey(e => e.Id);
            builder.Property(e => e.ProcessName).IsRequired();
            builder.Property(e => e.KeyPath).IsRequired();
            builder.Property(e => e.Operation).IsRequired();
            builder.HasIndex(e => e.OccurredAtUtc);
            builder.HasIndex(e => e.ProcessId);
            builder.HasIndex(e => e.IsSuspicious);
        });

        modelBuilder.Entity<MitreAttackMapping>(builder =>
        {
            builder.HasKey(m => m.Id);
            builder.Property(m => m.AlertType).IsRequired();
            builder.Property(m => m.TechniqueId).IsRequired();
            builder.Property(m => m.TechniqueName).IsRequired();
            builder.Property(m => m.Tactic).IsRequired();
            builder.HasIndex(m => m.AlertType).IsUnique();
        });

        modelBuilder.Entity<CustomIoc>(builder =>
        {
            builder.HasKey(c => c.Id);
            builder.Property(c => c.IocType).IsRequired();
            builder.Property(c => c.Value).IsRequired();
            builder.Property(c => c.Description).IsRequired();
            builder.HasIndex(c => new { c.IocType, c.Value });
            builder.HasIndex(c => c.IsActive);
        });

        modelBuilder.Entity<StixFeedSource>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.Name).IsRequired();
            builder.Property(s => s.Url).IsRequired();
            builder.Property(s => s.FeedType).IsRequired();
            builder.Property(s => s.LastStatus).IsRequired();
        });

        modelBuilder.Entity<StixIoc>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.IocType).IsRequired();
            builder.Property(s => s.Value).IsRequired();
            builder.HasIndex(s => s.FeedSourceId);
            builder.HasIndex(s => new { s.IocType, s.Value });
        });

        modelBuilder.Entity<AlertTriage>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.AlertType).IsRequired();
            builder.Property(a => a.Status).IsRequired();
            builder.Property(a => a.Notes).IsRequired();
            builder.Property(a => a.TriagedBy).IsRequired();
            builder.HasIndex(a => a.Status);
            builder.HasIndex(a => a.CreatedAtUtc);
            builder.HasIndex(a => a.IncidentId);
        });

        modelBuilder.Entity<Incident>(builder =>
        {
            builder.HasKey(i => i.Id);
            builder.Property(i => i.Title).IsRequired();
            builder.Property(i => i.Description).IsRequired();
            builder.Property(i => i.Status).IsRequired();
            builder.HasIndex(i => i.Status);
            builder.HasIndex(i => i.CreatedAtUtc);
            builder.HasIndex(i => i.Severity);
        });

        modelBuilder.Entity<AppWhitelistEntry>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.EntryType).IsRequired();
            builder.Property(a => a.Value).IsRequired();
            builder.Property(a => a.Description).IsRequired();
            builder.Property(a => a.Action).IsRequired();
            builder.HasIndex(a => new { a.EntryType, a.Value });
            builder.HasIndex(a => a.IsEnabled);
        });

        modelBuilder.Entity<PuaAlert>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.ProcessName).IsRequired();
            builder.Property(p => p.ImagePath).IsRequired();
            builder.Property(p => p.Category).IsRequired();
            builder.Property(p => p.DetectionReason).IsRequired();
            builder.Property(p => p.DetectionDetails).IsRequired();
            builder.HasIndex(p => p.DetectedAtUtc);
            builder.HasIndex(p => p.Category);
            builder.HasIndex(p => p.Severity);
        });

        modelBuilder.Entity<ScriptSandboxResult>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.ScriptType).IsRequired();
            builder.Property(s => s.ScriptHash).IsRequired().HasMaxLength(64);
            builder.Property(s => s.Verdict).IsRequired();
            builder.HasIndex(s => s.AnalyzedAtUtc);
            builder.HasIndex(s => s.Verdict);
        });

        modelBuilder.Entity<BrowserExtensionFinding>(builder =>
        {
            builder.HasKey(b => b.Id);
            builder.Property(b => b.Browser).IsRequired();
            builder.Property(b => b.ExtensionId).IsRequired();
            builder.Property(b => b.ExtensionName).IsRequired();
            builder.Property(b => b.Version).IsRequired();
            builder.HasIndex(b => b.AuditedAtUtc);
            builder.HasIndex(b => b.IsSuspicious);
        });

        modelBuilder.Entity<BrowserCredentialAccessAlert>(builder =>
        {
            builder.HasKey(b => b.Id);
            builder.Property(b => b.Browser).IsRequired();
            builder.Property(b => b.CredentialFilePath).IsRequired();
            builder.Property(b => b.AccessingProcess).IsRequired();
            builder.HasIndex(b => b.DetectedAtUtc);
            builder.HasIndex(b => b.Severity);
        });

        modelBuilder.Entity<CfgViolationAlert>(builder =>
        {
            builder.HasKey(c => c.Id);
            builder.Property(c => c.ProcessName).IsRequired();
            builder.Property(c => c.ViolationAddress).IsRequired();
            builder.Property(c => c.ExceptionCode).IsRequired();
            builder.Property(c => c.Details).IsRequired();
            builder.HasIndex(c => c.DetectedAtUtc);
            builder.HasIndex(c => c.Severity);
        });

        modelBuilder.Entity<AmsiBypassAlert>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.ProcessName).IsRequired();
            builder.Property(a => a.BypassMethod).IsRequired();
            builder.Property(a => a.Details).IsRequired();
            builder.Property(a => a.AffectedFunction).IsRequired();
            builder.HasIndex(a => a.DetectedAtUtc);
            builder.HasIndex(a => a.Severity);
        });

        modelBuilder.Entity<ApiCallSequenceAlert>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.ProcessName).IsRequired();
            builder.Property(a => a.ImagePath).IsRequired();
            builder.Property(a => a.ApiSequence).IsRequired();
            builder.Property(a => a.PatternName).IsRequired();
            builder.Property(a => a.DetectionReason).IsRequired();
            builder.HasIndex(a => a.DetectedAtUtc);
            builder.HasIndex(a => a.Severity);
        });

        modelBuilder.Entity<ParentChildAnomalyAlert>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.ParentProcessName).IsRequired();
            builder.Property(a => a.ChildProcessName).IsRequired();
            builder.Property(a => a.ChildCommandLine).IsRequired();
            builder.Property(a => a.AnomalyReason).IsRequired();
            builder.HasIndex(a => a.DetectedAtUtc);
            builder.HasIndex(a => a.Severity);
        });

        modelBuilder.Entity<ProcessCommandLineAlert>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.ProcessName).IsRequired();
            builder.Property(a => a.CommandLine).IsRequired();
            builder.Property(a => a.Triggers).IsRequired();
            builder.HasIndex(a => a.DetectedAtUtc);
            builder.HasIndex(a => a.Severity);
        });

        modelBuilder.Entity<NetworkBehaviorProfile>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.ProcessName).IsRequired();
            builder.Property(p => p.BaselineIps).IsRequired();
            builder.Property(p => p.BaselinePorts).IsRequired();
            builder.HasIndex(p => p.ProcessName).IsUnique();
            builder.HasIndex(p => p.LastUpdatedAtUtc);
        });

        modelBuilder.Entity<NetworkBehaviorAlert>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.ProcessName).IsRequired();
            builder.Property(a => a.UnexpectedIp).IsRequired();
            builder.Property(a => a.AnomalyReason).IsRequired();
            builder.HasIndex(a => a.DetectedAtUtc);
            builder.HasIndex(a => a.Severity);
        });

        modelBuilder.Entity<ThreatReport>(builder =>
        {
            builder.HasKey(r => r.Id);
            builder.Property(r => r.ReportType).IsRequired();
            builder.Property(r => r.OutputFilePath).IsRequired();
            builder.Property(r => r.TopThreatTypes).IsRequired();
            builder.HasIndex(r => r.GeneratedAtUtc);
            builder.HasIndex(r => r.ReportType);
        });

        modelBuilder.Entity<MemoryDumpResult>(builder =>
        {
            builder.HasKey(r => r.Id);
            builder.Property(r => r.ProcessName).IsRequired();
            builder.Property(r => r.DumpFilePath).IsRequired();
            builder.Property(r => r.ExtractedStrings).IsRequired();
            builder.Property(r => r.ExtractedIps).IsRequired();
            builder.Property(r => r.ExtractedUrls).IsRequired();
            builder.Property(r => r.SuspiciousImports).IsRequired();
            builder.HasIndex(r => r.CreatedAtUtc);
            builder.HasIndex(r => r.ProcessId);
        });

        modelBuilder.Entity<FirmwareVariableSnapshot>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.VariableName).IsRequired();
            builder.Property(s => s.VariableNamespace).IsRequired();
            builder.Property(s => s.CurrentValueHash).IsRequired();
            builder.Property(s => s.BaselineValueHash).IsRequired();
            builder.Property(s => s.ChangeDescription).IsRequired();
            builder.HasIndex(s => s.SnapshotAtUtc);
            builder.HasIndex(s => s.IsSuspicious);
        });

        modelBuilder.Entity<HypervisorDetectionResult>(builder =>
        {
            builder.HasKey(r => r.Id);
            builder.Property(r => r.HypervisorType).IsRequired();
            builder.Property(r => r.DetectionMethods).IsRequired();
            builder.Property(r => r.CpuidLeaf).IsRequired();
            builder.HasIndex(r => r.DetectedAtUtc);
            builder.HasIndex(r => r.IsVirtualMachine);
        });

        modelBuilder.Entity<KernelPatchGuardAlert>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.BypassMethodType).IsRequired();
            builder.Property(a => a.Details).IsRequired();
            builder.Property(a => a.TargetFunction).IsRequired();
            builder.HasIndex(a => a.DetectedAtUtc);
            builder.HasIndex(a => a.Severity);
        });

        modelBuilder.Entity<SupplyChainAlert>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.ProcessName).IsRequired();
            builder.Property(a => a.FilePath).IsRequired();
            builder.Property(a => a.Publisher).IsRequired();
            builder.Property(a => a.CertificateThumbprint).IsRequired();
            builder.Property(a => a.AlertType).IsRequired();
            builder.Property(a => a.Details).IsRequired();
            builder.HasIndex(a => a.DetectedAtUtc);
            builder.HasIndex(a => a.Severity);
        });

        modelBuilder.Entity<NotificationRecord>(builder =>
        {
            builder.HasKey(n => n.Id);
            builder.Property(n => n.NotificationType).IsRequired();
            builder.Property(n => n.Title).IsRequired();
            builder.Property(n => n.Message).IsRequired();
            builder.Property(n => n.Status).IsRequired();
            builder.Property(n => n.RelatedEntityType).IsRequired();
            builder.HasIndex(n => n.CreatedAtUtc);
            builder.HasIndex(n => n.Status);
        });

        modelBuilder.Entity<ScanProfile>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.Name).IsRequired();
            builder.Property(p => p.ProfileType).IsRequired();
            builder.Property(p => p.IncludePaths).IsRequired();
            builder.Property(p => p.ExcludePaths).IsRequired();
            builder.Property(p => p.FileExtensions).IsRequired();
            builder.HasIndex(p => p.IsDefault);
            builder.HasIndex(p => p.CreatedAtUtc);
        });
    }
}
