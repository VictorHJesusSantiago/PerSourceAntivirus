using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.LolBin.Commands.ScanLolBins;

public class ScanLolBinsCommandHandler(
    IRunningProcessProvider processProvider,
    ILolBinDetector detector,
    ILolBinAlertRepository repository)
    : IRequestHandler<ScanLolBinsCommand, ScanLolBinsResult>
{
    public async Task<ScanLolBinsResult> Handle(ScanLolBinsCommand request, CancellationToken cancellationToken)
    {
        var snapshots = processProvider.GetSnapshot();
        var descriptions = new List<string>();

        foreach (var snapshot in snapshots)
        {
            var commandLine = snapshot.ExecutablePath ?? string.Empty;
            var result = detector.Analyze(snapshot.ProcessName, commandLine);
            if (result is null)
                continue;

            var alert = new LolBinAlert
            {
                Id = Guid.NewGuid(),
                ProcessName = snapshot.ProcessName,
                Arguments = commandLine,
                LolbinName = result.LolbinName,
                Description = result.Description,
                MitreTechnique = result.MitreTechnique,
                Severity = result.Severity,
                AlertedAtUtc = DateTime.UtcNow
            };

            await repository.AddAsync(alert, cancellationToken);
            descriptions.Add($"[{result.MitreTechnique}] {result.LolbinName} (PID {snapshot.ProcessId}): {result.Description} (Severity {result.Severity})");
        }

        return new ScanLolBinsResult(descriptions.Count, descriptions.AsReadOnly());
    }
}
