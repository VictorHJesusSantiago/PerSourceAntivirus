using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Pe;

public sealed class ActiveLearningService : IActiveLearningService
{
    private const double LearningRate = 0.05;
    private const int Epochs = 200;

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly string _weightsFile;
    private readonly object _lock = new();
    private double[] _weights = [];
    private double _bias;
    private int _sampleCount;

    public int TrainingSampleCount { get { lock (_lock) return _sampleCount; } }

    public ActiveLearningService(IServiceScopeFactory scopeFactory, string weightsFile)
    {
        _scopeFactory = scopeFactory;
        _weightsFile = weightsFile;
        LoadWeights();
    }

    public async Task RecordSampleAsync(string filePath, bool isMalicious, CancellationToken ct = default)
    {
        var features = PeFeatureExtractor.Extract(filePath);
        if (features is null) return;

        string sha256;
        await using (var stream = File.OpenRead(filePath))
            sha256 = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false));

        var sample = new ActiveLearningSample
        {
            Id = Guid.NewGuid(),
            Sha256 = sha256,
            FeaturesJson = JsonSerializer.Serialize(features),
            IsMalicious = isMalicious,
            RecordedAtUtc = DateTime.UtcNow
        };

        using var scope = _scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IActiveLearningSampleRepository>();
        await repository.AddAsync(sample, ct).ConfigureAwait(false);
    }

    public async Task<int> RetrainAsync(CancellationToken ct = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IActiveLearningSampleRepository>();
        var samples = await repository.GetAllAsync(ct).ConfigureAwait(false);
        if (samples.Count < 10) return 0;

        var featureSets = samples
            .Select(s => (features: JsonSerializer.Deserialize<float[]>(s.FeaturesJson), label: s.IsMalicious ? 1.0 : 0.0))
            .Where(s => s.features is { Length: > 0 })
            .Select(s => (features: s.features!, s.label))
            .ToList();

        if (featureSets.Count < 10) return 0;

        int dims = featureSets[0].features.Length;
        var weights = new double[dims];
        double bias = 0;
        var rng = new Random(42);

        for (int epoch = 0; epoch < Epochs; epoch++)
        {
            foreach (var (features, label) in featureSets.OrderBy(_ => rng.Next()))
            {
                double z = bias;
                for (int i = 0; i < dims && i < features.Length; i++) z += weights[i] * features[i];
                double prediction = Sigmoid(z);
                double error = label - prediction;

                bias += LearningRate * error;
                for (int i = 0; i < dims && i < features.Length; i++)
                    weights[i] += LearningRate * error * features[i];
            }
        }

        lock (_lock)
        {
            _weights = weights;
            _bias = bias;
            _sampleCount = featureSets.Count;
        }

        SaveWeights(weights, bias);
        return featureSets.Count;
    }

    public float Predict(float[] features)
    {
        double[] weights;
        double bias;
        lock (_lock) { weights = _weights; bias = _bias; }

        if (weights.Length == 0) return 0f;

        double z = bias;
        for (int i = 0; i < weights.Length && i < features.Length; i++) z += weights[i] * features[i];
        return (float)Sigmoid(z);
    }

    private static double Sigmoid(double z) => 1.0 / (1.0 + Math.Exp(-z));

    private void LoadWeights()
    {
        if (!File.Exists(_weightsFile)) return;
        try
        {
            var json = File.ReadAllText(_weightsFile);
            var model = JsonSerializer.Deserialize<PersistedModel>(json);
            if (model is null) return;

            lock (_lock)
            {
                _weights = model.Weights;
                _bias = model.Bias;
                _sampleCount = model.SampleCount;
            }
        }
        catch { }
    }

    private void SaveWeights(double[] weights, double bias)
    {
        try
        {
            var dir = Path.GetDirectoryName(_weightsFile);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var model = new PersistedModel(weights, bias, weights.Length > 0 ? TrainingSampleCount : 0);
            File.WriteAllText(_weightsFile, JsonSerializer.Serialize(model));
        }
        catch { }
    }

    private sealed record PersistedModel(double[] Weights, double Bias, int SampleCount);
}
