using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Pe;

public class OnnxPeMlClassifier : IPeMlClassifier, IDisposable
{
    private const string OnnxFileName = "pe-classifier.onnx";
    private const float MaliciousThreshold = 0.65f;
    private const float SuspiciousThreshold = 0.35f;

    private readonly InferenceSession? _session;
    private bool _disposed;

    public string ModelVersion { get; }

    public OnnxPeMlClassifier(string modelsDirectory)
    {
        var modelPath = Path.Combine(modelsDirectory, OnnxFileName);
        if (File.Exists(modelPath))
        {
            try
            {
                var opts = new SessionOptions();
                opts.GraphOptimizationLevel = GraphOptimizationLevel.ORT_ENABLE_ALL;
                _session = new InferenceSession(modelPath, opts);
                ModelVersion = $"onnx:{Path.GetFileNameWithoutExtension(modelPath)}";
                return;
            }
            catch {  }
        }
        ModelVersion = "heuristic-v1";
    }

    public PeMlResult Classify(string filePath)
    {
        var features = PeFeatureExtractor.Extract(filePath);
        if (features is null)
            return new PeMlResult(0f, "NotPe", ModelVersion, [], []);

        float prob;
        if (_session is not null)
            prob = RunOnnx(features);
        else
            prob = HeuristicScore(features);

        var classification = prob >= MaliciousThreshold ? "Malicious"
            : prob >= SuspiciousThreshold ? "Suspicious"
            : "Clean";

        return new PeMlResult(prob, classification, ModelVersion, features, PeFeatureExtractor.FeatureNames);
    }

    private float RunOnnx(float[] features)
    {
        var tensor = new DenseTensor<float>(features, [1, features.Length]);
        var inputs = new List<NamedOnnxValue>
        {
            NamedOnnxValue.CreateFromTensor("features", tensor)
        };
        using var outputs = _session!.Run(inputs);
        var probs = outputs.First().AsEnumerable<float>().ToArray();
        return probs.Length >= 2 ? probs[1] : probs[0];
    }

    private static float HeuristicScore(float[] f)
    {
        var score = 0.0f;

        if (f[3] >= 7.5f) score += 0.30f;
        else if (f[3] >= 7.0f) score += 0.15f;

        score += Math.Min(f[17] * 0.08f, 0.25f);

        if (f[6] >= 2f) score += 0.15f;

        if (f[15] < 5f && f[9] < 0.5f)
            score += 0.20f;
        else if (f[15] < 5f)
            score += 0.05f;

        if (f[10] < 0.5f && f[9] < 0.5f && f[8] < 0.5f)
            score += 0.10f;

        if (f[11] > 0.5f && f[9] < 0.5f) score += 0.08f;

        if (f[1] > 12f || f[1] < 2f) score += 0.08f;

        score += Math.Min(f[28] * 0.10f, 0.20f);

        if (f[14] > 0.5f) score += 0.10f;

        if (f[29] < 0.001f || f[29] > 0.98f) score += 0.08f;

        if (f[0] < 4f) score += 0.10f;

        return Math.Clamp(score, 0f, 1f);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _session?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
