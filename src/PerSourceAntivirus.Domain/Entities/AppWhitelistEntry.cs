namespace PerSourceAntivirus.Domain.Entities;

public class AppWhitelistEntry
{
    public Guid Id { get; set; }
    public required string EntryType { get; set; }
    public required string Value { get; set; }
    public required string Description { get; set; }
    public required string Action { get; set; }
    public bool IsEnabled { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
