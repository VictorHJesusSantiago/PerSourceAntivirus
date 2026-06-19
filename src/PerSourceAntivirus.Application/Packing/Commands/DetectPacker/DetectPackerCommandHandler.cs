using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Packing.Commands.DetectPacker;

public class DetectPackerCommandHandler(IPackerDetector packerDetector)
    : IRequestHandler<DetectPackerCommand, DetectPackerResult>
{
    public async Task<DetectPackerResult> Handle(DetectPackerCommand request, CancellationToken cancellationToken)
    {
        var detection = await packerDetector.DetectAsync(request.FilePath, cancellationToken);

        return new DetectPackerResult(
            detection.PackerName,
            detection.IsPacked,
            detection.WasUnpacked);
    }
}
