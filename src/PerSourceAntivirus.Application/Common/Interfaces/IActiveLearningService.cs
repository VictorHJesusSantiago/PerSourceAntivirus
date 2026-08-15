namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IActiveLearningService
{
    Task RecordSampleAsync(string filePath, bool isMalicious, CancellationToken ct = default);
    Task<int> RetrainAsync(CancellationToken ct = default);
    float Predict(float[] features);
    int TrainingSampleCount { get; }
}
