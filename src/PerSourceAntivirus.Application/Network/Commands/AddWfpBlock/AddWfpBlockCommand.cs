using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Network.Commands.AddWfpBlock;

public record AddWfpBlockCommand(string IpAddress, string Reason = "") : IRequest<WfpBlockResult>;
