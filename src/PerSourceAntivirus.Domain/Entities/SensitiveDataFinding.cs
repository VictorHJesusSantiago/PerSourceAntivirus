namespace PerSourceAntivirus.Domain.Entities;

public class SensitiveDataFinding
{
    public Guid Id { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string DataType { get; set; } = string.Empty;
    public string MatchSnippet { get; set; } = string.Empty;
    public int LineNumber { get; set; }
    public int Severity { get; set; }
    public DateTime FoundAtUtc { get; set; }
}
