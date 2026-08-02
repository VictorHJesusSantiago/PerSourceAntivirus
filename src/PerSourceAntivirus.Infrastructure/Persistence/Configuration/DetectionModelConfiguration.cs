using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

// Detection-engine entities: ADS, archives, PDF/email, steganography and exploit prevention.
//
// [ADR-002] Split out of AppDbContext.OnModelCreating, which had grown to ~1,120 lines
// configuring 117 entities in one method. Kept as partial methods grouped by area rather
// than 117 separate IEntityTypeConfiguration<T> files: one-property-each classes would
// trade a God Class for 117 Lazy Elements. Configuration order is unchanged, so the
// generated model — and therefore the migration history — is byte-for-byte identical.
public partial class AppDbContext
{
    private static void ConfigureDetectionEntities(ModelBuilder modelBuilder)
    {
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

        modelBuilder.Entity<DllHijackAlert>(builder =>
        {
            builder.HasKey(d => d.Id);
            builder.Property(d => d.ProcessName).IsRequired();
            builder.Property(d => d.DllName).IsRequired();
            builder.Property(d => d.LoadedDllPath).IsRequired();
            builder.Property(d => d.HijackType).IsRequired();
            builder.HasIndex(d => d.DetectedAtUtc);
        });

        modelBuilder.Entity<CryptojackingAlert>(builder =>
        {
            builder.HasKey(c => c.Id);
            builder.Property(c => c.ProcessName).IsRequired();
            builder.Property(c => c.DetectionReason).IsRequired();
            builder.HasIndex(c => c.DetectedAtUtc);
        });

        modelBuilder.Entity<UnsignedBinaryAlert>(builder =>
        {
            builder.HasKey(u => u.Id);
            builder.Property(u => u.ProcessName).IsRequired();
            builder.Property(u => u.FilePath).IsRequired();
            builder.Property(u => u.Reason).IsRequired();
            builder.HasIndex(u => u.DetectedAtUtc);
        });

        modelBuilder.Entity<CustomSignatureMatch>(builder =>
        {
            builder.HasKey(c => c.Id);
            builder.Property(c => c.FilePath).IsRequired();
            builder.Property(c => c.FileHashSha256).IsRequired();
            builder.Property(c => c.SignatureName).IsRequired();
            builder.Property(c => c.MatchType).IsRequired();
            builder.HasIndex(c => c.DetectedAtUtc);
            builder.HasIndex(c => c.FileHashSha256);
        });

        modelBuilder.Entity<CertificateTrustEntry>(builder =>
        {
            builder.HasKey(c => c.Id);
            builder.Property(c => c.Thumbprint).IsRequired();
            builder.Property(c => c.SubjectName).IsRequired();
            builder.Property(c => c.TrustLevel).IsRequired();
            builder.HasIndex(c => c.Thumbprint).IsUnique();
        });

        modelBuilder.Entity<CertificateTrustAlert>(builder =>
        {
            builder.HasKey(c => c.Id);
            builder.Property(c => c.ProcessName).IsRequired();
            builder.Property(c => c.FilePath).IsRequired();
            builder.Property(c => c.Thumbprint).IsRequired();
            builder.Property(c => c.SubjectName).IsRequired();
            builder.Property(c => c.Reason).IsRequired();
            builder.HasIndex(c => c.DetectedAtUtc);
        });

        modelBuilder.Entity<ProcessFirewallRule>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.ProcessPath).IsRequired();
            builder.Property(p => p.Action).IsRequired();
            builder.HasIndex(p => p.ProcessPath);
        });

        modelBuilder.Entity<DnsTunnelingAlert>(builder =>
        {
            builder.HasKey(d => d.Id);
            builder.Property(d => d.SourceAddress).IsRequired();
            builder.Property(d => d.QueryDomain).IsRequired();
            builder.Property(d => d.DetectionReason).IsRequired();
            builder.HasIndex(d => d.DetectedAtUtc);
        });

        modelBuilder.Entity<GeoIpBlockAlert>(builder =>
        {
            builder.HasKey(g => g.Id);
            builder.Property(g => g.RemoteAddress).IsRequired();
            builder.Property(g => g.CountryCode).IsRequired();
            builder.Property(g => g.Direction).IsRequired();
            builder.HasIndex(g => g.DetectedAtUtc);
        });

        modelBuilder.Entity<SecureBootStatusSnapshot>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.BootloaderPath).IsRequired();
            builder.Property(s => s.BootloaderHashSha256).IsRequired();
            builder.HasIndex(s => s.CheckedAtUtc);
        });

        modelBuilder.Entity<UsbDeviceEvent>(builder =>
        {
            builder.HasKey(u => u.Id);
            builder.Property(u => u.PnpDeviceId).IsRequired();
            builder.Property(u => u.Description).IsRequired();
            builder.Property(u => u.ActionTaken).IsRequired();
            builder.HasIndex(u => u.DetectedAtUtc);
        });

        modelBuilder.Entity<ActiveLearningSample>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.Sha256).IsRequired();
            builder.Property(a => a.FeaturesJson).IsRequired();
            builder.HasIndex(a => a.RecordedAtUtc);
        });

        modelBuilder.Entity<RemoteAgentEvent>(builder =>
        {
            builder.HasKey(r => r.Id);
            builder.Property(r => r.SourceHost).IsRequired();
            builder.Property(r => r.DeviceVendor).IsRequired();
            builder.Property(r => r.DeviceProduct).IsRequired();
            builder.Property(r => r.SignatureId).IsRequired();
            builder.Property(r => r.Name).IsRequired();
            builder.HasIndex(r => r.ReceivedAtUtc);
        });

        modelBuilder.Entity<AuditLogChainEntry>(builder =>
        {
            builder.HasKey(a => a.Id);
            builder.Property(a => a.EventDescription).IsRequired();
            builder.Property(a => a.PreviousHash).IsRequired();
            builder.Property(a => a.EntryHash).IsRequired();
            builder.HasIndex(a => a.SequenceNumber).IsUnique();
        });

        modelBuilder.Entity<HostIsolationEvent>(builder =>
        {
            builder.HasKey(h => h.Id);
            builder.Property(h => h.Action).IsRequired();
            builder.Property(h => h.Reason).IsRequired();
            builder.HasIndex(h => h.TriggeredAtUtc);
        });

        modelBuilder.Entity<SampleSubmissionRecord>(builder =>
        {
            builder.HasKey(s => s.Id);
            builder.Property(s => s.OriginalFilePath).IsRequired();
            builder.Property(s => s.PackagedArchivePath).IsRequired();
            builder.HasIndex(s => s.CreatedAtUtc);
        });

        modelBuilder.Entity<ResponsePlaybookRule>(builder =>
        {
            builder.HasKey(r => r.Id);
            builder.Property(r => r.Name).IsRequired();
            builder.Property(r => r.TriggerAlertType).IsRequired();
            builder.Property(r => r.Actions).IsRequired();
        });

    }
}
