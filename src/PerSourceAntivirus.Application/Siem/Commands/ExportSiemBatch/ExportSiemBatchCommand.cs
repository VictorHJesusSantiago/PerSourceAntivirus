using MediatR;

namespace PerSourceAntivirus.Application.Siem.Commands.ExportSiemBatch;

public record ExportSiemBatchCommand(int MaxEvents = 100) : IRequest<int>;
