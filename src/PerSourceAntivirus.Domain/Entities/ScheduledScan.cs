namespace PerSourceAntivirus.Domain.Entities;

public class ScheduledScan
{
    public Guid Id { get; set; }
    public required string Path { get; set; }
    public int IntervalMinutes { get; set; }
    public bool IsEnabled { get; set; } = true;
    public DateTime? LastRunAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
