namespace PerSourceAntivirus.Domain.Entities;

public class UsbDeviceEvent
{
    public Guid Id { get; set; }
    public required string PnpDeviceId { get; set; }
    public required string Description { get; set; }
    public string? VendorProductId { get; set; }
    public bool WasAllowed { get; set; }
    public required string ActionTaken { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
