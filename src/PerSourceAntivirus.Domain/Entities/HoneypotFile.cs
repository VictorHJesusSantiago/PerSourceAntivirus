namespace PerSourceAntivirus.Domain.Entities;

public class HoneypotFile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string DecoyType { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastCheckedAtUtc { get; set; }
    public bool WasTouched { get; set; }
    public DateTime? TouchedAtUtc { get; set; }
}
