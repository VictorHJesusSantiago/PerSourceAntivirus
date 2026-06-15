using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Scans.Queries.GetScannedFiles;

public record GetScannedFilesQuery : IRequest<IReadOnlyList<ScannedFile>>;
