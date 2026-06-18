using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Network.Queries.GetWfpBlocks;

public record GetWfpBlocksQuery : IRequest<IReadOnlyList<WfpBlockEntry>>;
