namespace PerSourceAntivirus.Domain.Entities;

public class AtomBombingAlert
{
    public Guid Id { get; set; }
    public required string SuspiciousAtomContent { get; set; } // first 100 chars of atom name
    public ushort AtomId { get; set; }
    public double AtomContentEntropy { get; set; }
    public int AtomContentLength { get; set; }
    public required string SuspicionReason { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
