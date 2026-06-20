namespace PerSourceAntivirus.Application.Common.Interfaces;

public record ThreatTrendPoint(DateTime Date, int AlertCount, int CriticalCount);
public record ThreatTypeCount(string AlertType, int Count);

public interface IThreatTrendService
{
    Task<IReadOnlyList<ThreatTrendPoint>> GetDailyTrendAsync(int daysBack, CancellationToken ct = default);
    Task<IReadOnlyList<ThreatTypeCount>> GetTopThreatTypesAsync(int topN, CancellationToken ct = default);
}
