using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Ransomware.Queries.GetRansomwareAlerts;

public record GetRansomwareAlertsQuery(bool OnlyCritical = false) : IRequest<IReadOnlyList<RansomwareAlert>>;
