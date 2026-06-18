using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Pe.Commands.ClassifyPe;

public record ClassifyPeCommand(string FilePath) : IRequest<ClassifyPeResult>;

public record ClassifyPeResult(
    string FilePath,
    float MaliciousProbability,
    string Classification,
    string ModelVersion,
    bool IsPeFile
);
