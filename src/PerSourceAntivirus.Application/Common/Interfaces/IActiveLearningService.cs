namespace PerSourceAntivirus.Application.Common.Interfaces;

// Incremental "active learning" classifier: administrator-confirmed detections (from triage /
// quarantine actions) are recorded as labeled samples and periodically used to retrain a small
// online logistic-regression model over the same feature vector produced by PeFeatureExtractor.
// This complements IPeMlClassifier (ONNX/heuristic) rather than replacing it — full ONNX model
// re-training requires an external trainer and is out of scope for an in-process .NET runtime.
public interface IActiveLearningService
{
    Task RecordSampleAsync(string filePath, bool isMalicious, CancellationToken ct = default);
    Task<int> RetrainAsync(CancellationToken ct = default);
    float Predict(float[] features);
    int TrainingSampleCount { get; }
}
