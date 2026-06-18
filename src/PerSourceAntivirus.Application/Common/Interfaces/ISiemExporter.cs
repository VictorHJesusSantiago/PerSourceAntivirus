namespace PerSourceAntivirus.Application.Common.Interfaces;

public record SiemEventPayload(
    string DeviceVendor,
    string DeviceProduct,
    string DeviceVersion,
    int SignatureId,
    string Name,
    int Severity,
    DateTime OccurredAtUtc,
    string? SourceIp,
    string? DestinationIp,
    string? FileName,
    string? UserName,
    IDictionary<string, string>? Extensions
);

public interface ISiemExporter
{
    Task ExportAsync(SiemEventPayload evt, CancellationToken ct = default);
    Task ExportBatchAsync(IEnumerable<SiemEventPayload> events, CancellationToken ct = default);
    bool IsEnabled { get; }
}
