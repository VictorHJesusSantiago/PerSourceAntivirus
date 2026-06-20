using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IReportGenerator
{
    Task<ThreatReport> GenerateAsync(DateTime from, DateTime to, string reportType, string outputDirectory, CancellationToken ct = default);
    Task<ThreatReport> GenerateWeeklyAsync(string outputDirectory, CancellationToken ct = default);
    Task<ThreatReport> GenerateMonthlyAsync(string outputDirectory, CancellationToken ct = default);
}
