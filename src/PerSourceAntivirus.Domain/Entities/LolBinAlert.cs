namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class LolBinAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public required string Arguments { get; set; }
    public required string LolbinName { get; set; }
    public required string Description { get; set; }
    public required string MitreTechnique { get; set; }
    public int Severity { get; set; }  // 1-10
    public DateTime AlertedAtUtc { get; set; }
}
