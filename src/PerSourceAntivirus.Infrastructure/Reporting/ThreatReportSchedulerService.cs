using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Reporting;

public sealed class ThreatReportSchedulerService(IServiceScopeFactory scopeFactory, string outputDirectory) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(6);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(outputDirectory);
        DateTime? lastWeekly = null;
        DateTime? lastMonthly = null;

        while (!stoppingToken.IsCancellationRequested)
        {
            var now = DateTime.UtcNow;

            try
            {
                using var scope = scopeFactory.CreateScope();
                var generator = scope.ServiceProvider.GetRequiredService<IReportGenerator>();

                if (lastWeekly is null || (now - lastWeekly.Value).TotalDays >= 7)
                {
                    await generator.GenerateWeeklyAsync(outputDirectory, stoppingToken).ConfigureAwait(false);
                    lastWeekly = now;
                }

                if (lastMonthly is null || (now - lastMonthly.Value).TotalDays >= 30)
                {
                    await generator.GenerateMonthlyAsync(outputDirectory, stoppingToken).ConfigureAwait(false);
                    lastMonthly = now;
                }
            }
            catch (Exception) { }

            try { await Task.Delay(CheckInterval, stoppingToken); }
            catch (OperationCanceledException) { }
        }
    }
}
