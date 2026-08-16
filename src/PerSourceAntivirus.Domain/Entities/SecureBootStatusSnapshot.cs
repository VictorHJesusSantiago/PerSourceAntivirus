namespace PerSourceAntivirus.Domain.Entities;

public class SecureBootStatusSnapshot
{
    public Guid Id { get; set; }
    public bool SecureBootEnabled { get; set; }
    public required string BootloaderPath { get; set; }
    public bool BootloaderSigned { get; set; }
    public bool BootloaderTrusted { get; set; }
    public required string BootloaderHashSha256 { get; set; }
    public string? Anomalies { get; set; }
    public DateTime CheckedAtUtc { get; set; }
}
