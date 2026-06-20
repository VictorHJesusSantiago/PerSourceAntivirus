namespace PerSourceAntivirus.Domain.Entities;

public class ScriptSandboxResult
{
    public Guid Id { get; set; }
    public required string ScriptType { get; set; } // PowerShell/VBScript/JavaScript
    public required string ScriptHash { get; set; }
    public required string ScriptPreview { get; set; } // first 200 chars
    public int AmsiScore { get; set; }
    public bool WasSandboxed { get; set; }
    public required string BehavioralFindings { get; set; }
    public required string Verdict { get; set; } // Clean/Suspicious/Malicious
    public int Severity { get; set; }
    public DateTime AnalyzedAtUtc { get; set; }
}
