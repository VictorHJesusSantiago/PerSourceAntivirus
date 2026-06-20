namespace PerSourceAntivirus.Domain.Entities;

public class CustomIoc
{
    public Guid Id { get; set; }
    public required string IocType { get; set; } // Hash/IP/Domain/Yara/Mutex/ServiceName
    public required string Value { get; set; }
    public required string Description { get; set; }
    public required string Tags { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? LastMatchedAtUtc { get; set; }
}
