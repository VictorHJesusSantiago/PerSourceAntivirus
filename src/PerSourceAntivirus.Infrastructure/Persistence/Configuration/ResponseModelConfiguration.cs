using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public partial class AppDbContext
{
    private static void ConfigureResponseEntities(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<PlaybookExecutionLog>(builder =>
        {
            builder.HasKey(p => p.Id);
            builder.Property(p => p.RuleName).IsRequired();
            builder.Property(p => p.AlertType).IsRequired();
            builder.Property(p => p.ActionsExecuted).IsRequired();
            builder.HasIndex(p => p.ExecutedAtUtc);
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

    }
}
