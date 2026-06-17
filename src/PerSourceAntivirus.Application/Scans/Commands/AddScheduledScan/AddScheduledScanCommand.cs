using MediatR;

namespace PerSourceAntivirus.Application.Scans.Commands.AddScheduledScan;

public record AddScheduledScanCommand(string Path, int IntervalMinutes) : IRequest<AddScheduledScanResult>;
