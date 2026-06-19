using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Emulation.Commands.EmulateFile;

public class EmulateFileCommandHandler(ICpuEmulator cpuEmulator)
    : IRequestHandler<EmulateFileCommand, EmulateFileResult>
{
    private const long MaxFileSizeBytes = 10 * 1024 * 1024; // 10 MB

    public async Task<EmulateFileResult> Handle(EmulateFileCommand request, CancellationToken cancellationToken)
    {
        var fileInfo = new FileInfo(request.FilePath);

        if (!fileInfo.Exists)
        {
            return new EmulateFileResult(false, 0, []);
        }

        if (fileInfo.Length > MaxFileSizeBytes)
        {
            return new EmulateFileResult(false, 0, ["FileTooLarge"]);
        }

        var bytes = await File.ReadAllBytesAsync(request.FilePath, cancellationToken);

        var summary = await cpuEmulator.EmulateAsync(request.FilePath, bytes, ct: cancellationToken);

        return new EmulateFileResult(
            summary.IsSuspicious,
            summary.InstructionCount,
            summary.DetectedPatterns);
    }
}
