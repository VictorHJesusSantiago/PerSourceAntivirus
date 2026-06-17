namespace PerSourceAntivirus.Domain.Entities;

public class OfficeMacroAnalysisResult
{
    public Guid Id { get; set; }
    public Guid ScannedFileId { get; set; }
    public ScannedFile ScannedFile { get; set; } = null!;
    public bool HasMacros { get; set; }
    public bool HasAutoExec { get; set; }
    public bool HasNetworkAccess { get; set; }
    public bool HasProcessExecution { get; set; }
    public bool HasObfuscation { get; set; }
    public string SuspiciousPatterns { get; set; } = string.Empty;
}
