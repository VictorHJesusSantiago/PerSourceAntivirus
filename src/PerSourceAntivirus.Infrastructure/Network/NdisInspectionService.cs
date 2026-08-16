using System.Runtime.Versioning;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class NdisInspectionService : INdisInspectionService
{
    private const string NdisServiceName = "PSAVNdisFilter";

    public string DriverServiceName => NdisServiceName;

    public bool IsDriverLoaded { get; private set; }

    public Task<bool> CheckDriverStatusAsync(CancellationToken ct = default)
    {
        try
        {
            var keyPath = $@"SYSTEM\CurrentControlSet\Services\{NdisServiceName}";
            using var key = Registry.LocalMachine.OpenSubKey(keyPath);
            if (key is null)
            {
                IsDriverLoaded = false;
                return Task.FromResult(false);
            }

            var imagePath = key.GetValue("ImagePath") as string;
            IsDriverLoaded = !string.IsNullOrEmpty(imagePath);
            return Task.FromResult(IsDriverLoaded);
        }
        catch
        {
            IsDriverLoaded = false;
            return Task.FromResult(false);
        }
    }
}
