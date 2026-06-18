using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Process.Commands.ScanProcessMemory;

public record ScanProcessMemoryCommand(int ProcessId) : IRequest<ProcessMemoryScanResult>;
