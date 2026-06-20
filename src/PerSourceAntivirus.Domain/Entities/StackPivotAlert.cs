namespace PerSourceAntivirus.Domain.Entities;

public class StackPivotAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public int ThreadId { get; set; }
    public ulong RspValue { get; set; }
    public ulong StackBase { get; set; }
    public ulong StackLimit { get; set; }
    public required string SuspicionReason { get; set; } // "RspOutsideStackRange","RspInHeapRegion"
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
