using MediatR;

namespace PerSourceAntivirus.Application.LolBin.Commands.ScanLolBins;

public record ScanLolBinsCommand : IRequest<ScanLolBinsResult>;
public record ScanLolBinsResult(int AlertsFound, IReadOnlyList<string> AlertDescriptions);
