using System.Management;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Wsc;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IWscRegistration, WscRegistrationService>();
[SupportedOSPlatform("windows")]
public sealed class WscRegistrationService : IWscRegistration
{
    private const string WscNamespace = @"root\SecurityCenter2";
    private const string ProductClass = "AntiVirusProduct";
    private ManagementObject? _registeredProduct;

    public bool IsRegistered => _registeredProduct != null;

    public Task RegisterAsync(CancellationToken ct = default)
    {
        try
        {
            var scope = new ManagementScope($@"\\.\{WscNamespace}");
            scope.Connect();

            var managementClass = new ManagementClass(scope, new ManagementPath(ProductClass), null);
            var instance = managementClass.CreateInstance();
            if (instance == null) return Task.CompletedTask;

            var exePath = Environment.ProcessPath
                ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                ?? "psav.exe";

            instance["displayName"] = "PerSource Antivirus";
            instance["instanceGuid"] = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567891}";
            instance["pathToSignedProductExe"] = exePath;
            instance["pathToSignedReportingExe"] = exePath;
            instance["productState"] = 397312;  // 0x61100 = enabled, up-to-date, real-time on

            instance.Put();
            _registeredProduct = instance;
        }
        catch
        {
            // WSC registration requires elevation and specific Windows versions
        }
        return Task.CompletedTask;
    }

    public Task UnregisterAsync(CancellationToken ct = default)
    {
        try
        {
            _registeredProduct?.Delete();
            _registeredProduct?.Dispose();
            _registeredProduct = null;
        }
        catch { }
        return Task.CompletedTask;
    }
}
