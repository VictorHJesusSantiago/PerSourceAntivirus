namespace PerSourceAntivirus.Domain.Entities;

public class NotificationRecord
{
    public Guid Id { get; set; }
    public required string NotificationType { get; set; }
    public required string Title { get; set; }
    public required string Message { get; set; }
    public int Severity { get; set; }
    public required string Status { get; set; }
    public required string RelatedEntityType { get; set; }
    public Guid? RelatedEntityId { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? AcknowledgedAtUtc { get; set; }
}
