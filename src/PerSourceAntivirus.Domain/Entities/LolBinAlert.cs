namespace PerSourceAntivirus.Domain.Entities;

public class LolBinAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public required string Arguments { get; set; }
    public required string LolbinName { get; set; }
    public required string Description { get; set; }
    public required string MitreTechnique { get; set; }
    public int Severity { get; set; }
    public DateTime AlertedAtUtc { get; set; }
}
