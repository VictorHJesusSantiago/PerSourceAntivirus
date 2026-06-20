namespace PerSourceAntivirus.Domain.Entities;

public class FirmwareVariableSnapshot
{
    public Guid Id { get; set; }
    public required string VariableName { get; set; }
    public required string VariableNamespace { get; set; }
    public required string CurrentValueHash { get; set; }
    public required string BaselineValueHash { get; set; }
    public bool IsSuspicious { get; set; }
    public required string ChangeDescription { get; set; }
    public DateTime SnapshotAtUtc { get; set; }
}
