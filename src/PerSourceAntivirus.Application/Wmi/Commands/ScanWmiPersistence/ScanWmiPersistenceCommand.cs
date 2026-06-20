using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Wmi.Commands.ScanWmiPersistence;

public record ScanWmiPersistenceCommand : IRequest<IReadOnlyList<WmiPersistenceAlert>>;
