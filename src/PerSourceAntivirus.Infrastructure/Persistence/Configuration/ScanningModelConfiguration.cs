using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

// Scanned files, YARA/PE/script analysis, network + process events, MBR and ransomware.
//
// [ADR-002] Split out of AppDbContext.OnModelCreating, which had grown to ~1,120 lines
// configuring 117 entities in one method. Kept as partial methods grouped by area rather
// than 117 separate IEntityTypeConfiguration<T> files: one-property-each classes would
// trade a God Class for 117 Lazy Elements. Configuration order is unchanged, so the
// generated model — and therefore the migration history — is byte-for-byte identical.
public partial class AppDbContext
{
    private static void ConfigureScanningEntities(ModelBuilder modelBuilder)
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

    }
}
