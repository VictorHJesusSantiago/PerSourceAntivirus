using MediatR;

namespace PerSourceAntivirus.Application.Ransomware.Commands.SetupHoneypot;

public record SetupHoneypotCommand : IRequest<SetupHoneypotResult>;

public record SetupHoneypotResult(int FilesCreated, IReadOnlyList<string> Paths);
