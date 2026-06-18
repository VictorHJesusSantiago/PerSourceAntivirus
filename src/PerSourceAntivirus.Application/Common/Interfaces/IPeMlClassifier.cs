namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPeMlClassifier
{
    PeMlResult Classify(string filePath);
    string ModelVersion { get; }
}

public record PeMlResult(
    float MaliciousProbability,
    string Classification,    // "Malicious" | "Suspicious" | "Clean"
    string ModelVersion,
    float[] Features,
    string[] FeatureNames
);
