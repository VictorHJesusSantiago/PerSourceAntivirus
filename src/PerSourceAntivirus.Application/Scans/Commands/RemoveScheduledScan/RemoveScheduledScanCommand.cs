using MediatR;

namespace PerSourceAntivirus.Application.Scans.Commands.RemoveScheduledScan;

public record RemoveScheduledScanCommand(Guid Id) : IRequest<Unit>;
