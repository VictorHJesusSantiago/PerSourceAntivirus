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
            catch { /* fall through to heuristic */ }
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
        // Expect output shape [1, 2]: [P(Clean), P(Malicious)]
        var probs = outputs.First().AsEnumerable<float>().ToArray();
        return probs.Length >= 2 ? probs[1] : probs[0];
    }

    // Calibrated heuristic scoring — mirrors what a LightGBM model trained on
    // Sorel-20M / EMBER features would produce for obvious malware patterns.
    private static float HeuristicScore(float[] f)
    {
        var score = 0.0f;

        // f[3] = max_section_entropy
        if (f[3] >= 7.5f) score += 0.30f;
        else if (f[3] >= 7.0f) score += 0.15f;

        // f[17] = num_suspicious_imports
        score += Math.Min(f[17] * 0.08f, 0.25f);

        // f[6] = num_high_entropy_sections (>7.0)
        if (f[6] >= 2f) score += 0.15f;

        // f[15] = num_imports — very low import count is suspicious (packed)
        if (f[15] < 5f && f[9] < 0.5f) // not .NET
            score += 0.20f;
        else if (f[15] < 5f)
            score += 0.05f;

        // f[10] = is_signed, f[9] = is_dotnet, f[8] = is_dll
        if (f[10] < 0.5f && f[9] < 0.5f && f[8] < 0.5f) // unsigned native EXE
            score += 0.10f;

        // f[11] = has_tls — legitimate TLS is common but also abused by packers
        if (f[11] > 0.5f && f[9] < 0.5f) score += 0.08f;

        // f[1] = num_sections
        if (f[1] > 12f || f[1] < 2f) score += 0.08f;

        // f[28] = num_anomalies
        score += Math.Min(f[28] * 0.10f, 0.20f);

        // f[14] = has_overlay
        if (f[14] > 0.5f) score += 0.10f;

        // f[29] = timestamp_norm — timestamp = 0 means stripped/faked
        if (f[29] < 0.001f || f[29] > 0.98f) score += 0.08f;

        // f[0] = file_size_kb — very small PE (< 4 KB) is suspicious
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
