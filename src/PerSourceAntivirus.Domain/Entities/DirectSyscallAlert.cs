namespace PerSourceAntivirus.Domain.Entities;

public class DirectSyscallAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public ulong SyscallInstructionAddress { get; set; }
    public required string InstructionType { get; set; }
    public required string ContainingModulePath { get; set; }
    public bool IsInSystemModule { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
