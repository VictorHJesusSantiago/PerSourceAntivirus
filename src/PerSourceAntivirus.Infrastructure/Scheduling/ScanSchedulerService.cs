using MediatR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Scans.Commands.ScanDirectory;

namespace PerSourceAntivirus.Infrastructure.Scheduling;

public class ScanSchedulerService(IServiceScopeFactory scopeFactory) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);

            using var scope = scopeFactory.CreateScope();
            var repo = scope.ServiceProvider.GetRequiredService<IScheduledScanRepository>();
            var mediator = scope.ServiceProvider.GetRequiredService<IMediator>();

            try
            {
                var dueScans = await repo.GetDueScansAsync(stoppingToken);
                foreach (var scan in dueScans)
                {
                    await mediator.Send(new ScanDirectoryCommand(scan.Path), stoppingToken);
                    await repo.UpdateLastRunAsync(scan.Id, DateTime.UtcNow, stoppingToken);
                }
            }
            catch (Exception) { }
        }
    }
}
