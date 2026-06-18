namespace PerSourceAntivirus.Domain.Entities;

public class MbrSnapshot
{
    public Guid Id { get; set; }
    public int DriveIndex { get; set; }
    public string Sha256Hash { get; set; } = string.Empty;
    public int SectorSize { get; set; }
    public DateTime TakenAtUtc { get; set; }
    public bool IsBaseline { get; set; }
}
