namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPeMlClassifier
{
    PeMlResult Classify(string filePath);
    string ModelVersion { get; }
}

public record PeMlResult(
    float MaliciousProbability,
    string Classification,
    string ModelVersion,
    float[] Features,
    string[] FeatureNames
);
