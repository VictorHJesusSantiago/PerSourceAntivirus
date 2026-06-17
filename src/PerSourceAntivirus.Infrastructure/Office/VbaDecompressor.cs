using System.Text;

namespace PerSourceAntivirus.Infrastructure.Office;

/// <summary>
/// Decompresses VBA streams using the MS-OVBA compression algorithm (MS-OVBA §2.4.1).
/// </summary>
public static class VbaDecompressor
{
    /// <summary>
    /// Scans <paramref name="data"/> for the 0x01 compression signature, then decompresses.
    /// Returns an empty array when the signature is absent or the data is malformed.
    /// </summary>
    public static byte[] Decompress(byte[] data)
    {
        // The signature byte 0x01 separates the uncompressed module header from the
        // compressed source.  We search from the end so we skip over any occurrences
        // in the fixed-size header portion of the module stream.
        int sigIndex = -1;
        for (int i = data.Length - 1; i >= 0; i--)
        {
            if (data[i] == 0x01)
            {
                sigIndex = i;
                break;
            }
        }
        if (sigIndex < 0 || sigIndex + 3 > data.Length) return [];

        int src = sigIndex + 1;
        var dest = new List<byte>(Math.Max(4096, data.Length * 4));

        while (src + 2 <= data.Length)
        {
            ushort chunkHeader = (ushort)(data[src] | (data[src + 1] << 8));
            src += 2;

            bool isCompressed  = (chunkHeader & 0x8000) != 0;
            int  compressedLen = (chunkHeader & 0x0FFF) + 3;
            int  chunkEnd      = Math.Min(src + compressedLen, data.Length);
            int  chunkStart    = dest.Count;

            if (!isCompressed)
            {
                // Raw chunk: always 4096 literal bytes.
                int count = Math.Min(4096, data.Length - src);
                for (int i = 0; i < count; i++) dest.Add(data[src + i]);
                src += count;
            }
            else
            {
                while (src < chunkEnd)
                {
                    byte flags = data[src++];

                    for (int bit = 0; bit < 8 && src < chunkEnd; bit++)
                    {
                        if ((flags & (1 << bit)) == 0)
                        {
                            // Literal byte.
                            dest.Add(data[src++]);
                        }
                        else
                        {
                            // Copy token: 2 bytes, little-endian.
                            if (src + 2 > chunkEnd) { src++; break; }
                            ushort token = (ushort)(data[src] | (data[src + 1] << 8));
                            src += 2;

                            // Bit-split depends on how many bytes have been decompressed
                            // within the CURRENT chunk so far (window position).
                            int winPos   = dest.Count - chunkStart;
                            int bitCount = ComputeBitCount(winPos);

                            int lenBits  = 16 - bitCount;
                            int lenMask  = (1 << lenBits) - 1;
                            int offMask  = ~lenMask & 0xFFFF;

                            int copyLen    = (token & lenMask) + 3;
                            int copyOffset = ((token & offMask) >> lenBits) + 1;
                            int copyFrom   = dest.Count - copyOffset;

                            if (copyFrom < 0) continue; // malformed token

                            for (int i = 0; i < copyLen; i++)
                            {
                                int idx = copyFrom + i;
                                if (idx >= dest.Count) break;
                                dest.Add(dest[idx]);
                            }
                        }
                    }
                }
            }
        }

        return dest.Count == 0 ? [] : dest.ToArray();
    }

    /// <summary>
    /// Extracts printable ASCII lines from a byte array, useful for scanning raw
    /// streams that may not be fully decompressible.
    /// </summary>
    public static string ExtractPrintableText(byte[] data)
    {
        var sb = new StringBuilder(data.Length);
        foreach (byte b in data)
        {
            char c = (char)b;
            if (c is >= ' ' and <= '~' or '\r' or '\n' or '\t')
                sb.Append(c);
        }
        return sb.ToString();
    }

    // MS-OVBA §2.4.1.3.6: number of offset bits = ceil(log2(max(winPos,1))), min 4.
    private static int ComputeBitCount(int winPos)
    {
        if (winPos <= 16) return 4;
        int n = winPos - 1, bits = 0;
        while (n > 0) { n >>= 1; bits++; }
        return Math.Max(bits, 4);
    }
}
