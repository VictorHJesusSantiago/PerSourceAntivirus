using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public partial class AppDbContext
{
    private static void ConfigureTelemetryEntities(ModelBuilder modelBuilder)
    {
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
