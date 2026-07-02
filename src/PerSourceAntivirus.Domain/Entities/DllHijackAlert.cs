namespace PerSourceAntivirus.Domain.Entities;

public class DllHijackAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string DllName { get; set; }
    public required string LoadedDllPath { get; set; }
    public string? ExpectedSystemDllPath { get; set; }
    public required string HijackType { get; set; } // SearchOrderHijack | MissingKnownDllSideload | UnsignedSystemDllName
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
