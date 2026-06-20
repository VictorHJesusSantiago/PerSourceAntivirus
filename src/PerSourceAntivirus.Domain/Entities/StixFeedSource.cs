namespace PerSourceAntivirus.Domain.Entities;

public class StixFeedSource
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public required string Url { get; set; }
    public required string FeedType { get; set; } // STIX/TAXII/JSON
    public bool IsEnabled { get; set; }
    public DateTime? LastUpdatedAtUtc { get; set; }
    public required string LastStatus { get; set; }
    public int IocCount { get; set; }
}
