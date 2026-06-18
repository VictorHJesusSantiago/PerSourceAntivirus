using System.Text.Json;
using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Pe.Commands.ClassifyPe;

public class ClassifyPeCommandHandler(IPeMlClassifier classifier, IPeMlPredictionRepository repo)
    : IRequestHandler<ClassifyPeCommand, ClassifyPeResult>
{
    public async Task<ClassifyPeResult> Handle(ClassifyPeCommand request, CancellationToken cancellationToken)
    {
        if (!File.Exists(request.FilePath))
            return new ClassifyPeResult(request.FilePath, 0f, "Unknown", classifier.ModelVersion, false);

        var result = classifier.Classify(request.FilePath);
        if (result.Classification == "NotPe")
            return new ClassifyPeResult(request.FilePath, 0f, "NotPe", result.ModelVersion, false);

        var featureDict = result.FeatureNames
            .Zip(result.Features, (name, value) => new { name, value })
            .ToDictionary(x => x.name, x => (object)x.value);

        await repo.AddAsync(new PeMlPrediction
        {
            FilePath = request.FilePath,
            MaliciousProbability = result.MaliciousProbability,
            Classification = result.Classification,
            ModelVersion = result.ModelVersion,
            PredictedAtUtc = DateTime.UtcNow,
            FeaturesJson = JsonSerializer.Serialize(featureDict)
        }, cancellationToken);

        return new ClassifyPeResult(
            request.FilePath,
            result.MaliciousProbability,
            result.Classification,
            result.ModelVersion,
            true);
    }
}
