using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Process.Commands.ScanProcessMemory;

public class ScanProcessMemoryCommandHandler(IProcessMemoryScanner scanner)
    : IRequestHandler<ScanProcessMemoryCommand, ProcessMemoryScanResult>
{
    public Task<ProcessMemoryScanResult> Handle(ScanProcessMemoryCommand request, CancellationToken cancellationToken)
        => scanner.ScanProcessAsync(request.ProcessId, cancellationToken);
}
