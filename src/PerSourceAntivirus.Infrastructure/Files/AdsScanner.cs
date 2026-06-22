using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Files;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IAdsScanner, AdsScanner>();
[SupportedOSPlatform("windows")]
public sealed class AdsScanner : IAdsScanner
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint FindFirstStreamW(string lpFileName, int InfoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextStreamW(nint hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(nint hFindFile);

    private const nint INVALID_HANDLE_VALUE = -1;

    public IReadOnlyList<AdsStreamData> ScanStreams(string filePath)
    {
        var results = new List<AdsStreamData>();

        try
        {
            nint handle = FindFirstStreamW(filePath, 0, out var streamData, 0);
            if (handle == INVALID_HANDLE_VALUE) return results;

            try
            {
                do
                {
                    var name = streamData.cStreamName;
                    // Skip the main data stream "::$DATA"
                    if (name.Equals("::$DATA", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var isSuspicious = false;
                    var reason = "Clean";

                    // Large ADS (>= 4 KB) is suspicious
                    if (streamData.StreamSize >= 4096)
                    {
                        isSuspicious = true;
                        reason = "LargeHiddenData";
                    }

                    // Try to read the stream content for further analysis
                    try
                    {
                        var streamPath = $"{filePath}{name}";
                        var bytes = System.IO.File.ReadAllBytes(streamPath);

                        // Check for PE header (MZ)
                        if (bytes.Length >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A)
                        {
                            isSuspicious = true;
                            reason = "HasPeHeader";
                        }
                        // Check for script content
                        else if (bytes.Length > 10)
                        {
                            var text = System.Text.Encoding.UTF8.GetString(bytes, 0, Math.Min(bytes.Length, 256));
                            if (text.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                                text.Contains("<script", StringComparison.OrdinalIgnoreCase) ||
                                text.Contains("WScript", StringComparison.OrdinalIgnoreCase) ||
                                text.Contains("eval(", StringComparison.OrdinalIgnoreCase))
                            {
                                isSuspicious = true;
                                reason = "HasScript";
                            }
                        }
                    }
                    catch { }

                    results.Add(new AdsStreamData(name, streamData.StreamSize, isSuspicious, reason));
                }
                while (FindNextStreamW(handle, out streamData));
            }
            finally
            {
                FindClose(handle);
            }
        }
        catch { }

        return results;
    }
}
