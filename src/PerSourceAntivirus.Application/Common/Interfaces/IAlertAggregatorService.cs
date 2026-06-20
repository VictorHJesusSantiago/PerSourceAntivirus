namespace PerSourceAntivirus.Application.Common.Interfaces;

public record AggregatedAlert(string AlertType, Guid AlertId, string Summary,
    int Severity, DateTime DetectedAt, string ProcessName);

public interface IAlertAggregatorService
{
    Task<IReadOnlyList<AggregatedAlert>> GetRecentAlertsAsync(int count = 100, CancellationToken ct = default);
    Task<IReadOnlyList<AggregatedAlert>> GetAlertsByTypeAsync(string alertType, CancellationToken ct = default);
}
