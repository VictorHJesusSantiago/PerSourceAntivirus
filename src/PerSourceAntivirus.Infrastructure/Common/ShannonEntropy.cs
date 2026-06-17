namespace PerSourceAntivirus.Infrastructure.Common;

public static class ShannonEntropy
{
    public static double Calculate(byte[] data)
    {
        if (data.Length == 0)
        {
            return 0;
        }

        var byteCounts = new long[256];
        foreach (var b in data)
        {
            byteCounts[b]++;
        }

        return Calculate(byteCounts, data.Length);
    }

    public static double Calculate(long[] byteCounts, long totalBytes)
    {
        if (totalBytes == 0)
        {
            return 0;
        }

        var entropy = 0.0;
        foreach (var count in byteCounts)
        {
            if (count == 0)
            {
                continue;
            }

            var probability = (double)count / totalBytes;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}
