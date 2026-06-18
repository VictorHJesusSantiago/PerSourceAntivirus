using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Ransomware.Queries.GetHoneypots;

public record GetHoneypotsQuery : IRequest<IReadOnlyList<HoneypotFile>>;
