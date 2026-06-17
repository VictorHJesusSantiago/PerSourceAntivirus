using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Domain.Entities;

public class ScriptAnalysisResult
{
    public Guid Id { get; set; }
    public Guid ScannedFileId { get; set; }
    public ScannedFile ScannedFile { get; set; } = null!;
    public ScriptType ScriptType { get; set; }
    public bool HasObfuscation { get; set; }
    public bool HasNetworkAccess { get; set; }
    public bool HasProcessExecution { get; set; }
    public bool HasFileSystemAccess { get; set; }
    public string SuspiciousPatterns { get; set; } = string.Empty;
}
