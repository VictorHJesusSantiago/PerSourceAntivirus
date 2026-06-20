namespace PerSourceAntivirus.Domain.Entities;

public class NetworkBehaviorProfile
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public required string BaselineIps { get; set; }
    public required string BaselinePorts { get; set; }
    public int ObservationCount { get; set; }
    public DateTime FirstSeenAtUtc { get; set; }
    public DateTime LastUpdatedAtUtc { get; set; }
}
