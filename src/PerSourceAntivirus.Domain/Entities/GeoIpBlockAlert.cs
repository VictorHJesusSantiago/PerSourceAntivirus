namespace PerSourceAntivirus.Domain.Entities;

public class GeoIpBlockAlert
{
    public Guid Id { get; set; }
    public required string RemoteAddress { get; set; }
    public required string CountryCode { get; set; }
    public required string Direction { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
