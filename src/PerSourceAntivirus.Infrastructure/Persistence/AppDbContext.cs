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
    }
}
