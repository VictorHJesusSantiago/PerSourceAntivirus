using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Ransomware.Commands.SetupHoneypot;

public class SetupHoneypotCommandHandler(IHoneypotManager honeypotManager, IHoneypotRepository repo)
    : IRequestHandler<SetupHoneypotCommand, SetupHoneypotResult>
{
    public async Task<SetupHoneypotResult> Handle(SetupHoneypotCommand request, CancellationToken cancellationToken)
    {
        var paths = await honeypotManager.SetupHoneypotsAsync(cancellationToken);
        foreach (var path in paths)
        {
            await repo.AddAsync(new HoneypotFile
            {
                FilePath = path,
                FileName = Path.GetFileName(path),
                DecoyType = Path.GetExtension(path).TrimStart('.'),
                CreatedAtUtc = DateTime.UtcNow
            }, cancellationToken);
        }
        return new SetupHoneypotResult(paths.Count, paths);
    }
}
