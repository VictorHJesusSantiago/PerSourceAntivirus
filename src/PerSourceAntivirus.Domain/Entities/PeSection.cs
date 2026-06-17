namespace PerSourceAntivirus.Domain.Entities;

public class PeSection
{
    public Guid Id { get; set; }

    public Guid PeAnalysisResultId { get; set; }

    public PeAnalysisResult? PeAnalysisResult { get; set; }

    public required string Name { get; set; }

    public uint SizeOfRawData { get; set; }

    public double Entropy { get; set; }
}
