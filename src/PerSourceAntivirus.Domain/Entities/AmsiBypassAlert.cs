namespace PerSourceAntivirus.Domain.Entities;

public class AmsiBypassAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string BypassMethod { get; set; } // PatchAmsiScanBuffer/UnloadAmsiDll/FakeContext
    public required string Details { get; set; }
    public required string AffectedFunction { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
