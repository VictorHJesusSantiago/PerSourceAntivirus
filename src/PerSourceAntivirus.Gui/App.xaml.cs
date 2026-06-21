using System.Windows;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PerSourceAntivirus.Application;
using PerSourceAntivirus.Gui.Services;
using PerSourceAntivirus.Gui.ViewModels;
using PerSourceAntivirus.Infrastructure;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Gui;

public partial class App
{
    private IHost? _host;
    private TrayIconService? _tray;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _host = Host.CreateDefaultBuilder()
            .ConfigureAppConfiguration(cfg =>
                cfg.AddJsonFile("appsettings.json", optional: true))
            .ConfigureServices((ctx, services) =>
            {
                services.AddApplicationServices();
                services.AddInfrastructureServices(ctx.Configuration);

                services.AddSingleton<MainViewModel>();
                services.AddTransient<DashboardViewModel>();
                services.AddTransient<ThreatsViewModel>();
                services.AddTransient<QuarantineViewModel>();
                services.AddTransient<AlertsViewModel>();
                services.AddTransient<NotificationsViewModel>();
                services.AddTransient<SettingsViewModel>();
                services.AddTransient<ExclusionsViewModel>();
                services.AddTransient<ScanProfilesViewModel>();
                services.AddTransient<ReportsViewModel>();
                services.AddTransient<SystemStatusViewModel>();
                services.AddTransient<TimelineViewModel>();
                services.AddTransient<HuntViewModel>();
                services.AddTransient<ToastNotificationService>();
                services.AddSingleton<SafeModeScanScheduler>();
                services.AddSingleton<TrayIconService>();
                services.AddSingleton<MainWindow>();
            })
            .Build();

        await _host.StartAsync();

        // Apply pending EF migrations
        try
        {
            using var scope = _host.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Database.MigrateAsync();
        }
        catch { /* non-fatal */ }

        _tray = _host.Services.GetRequiredService<TrayIconService>();
        _tray.Initialize();

        var window = _host.Services.GetRequiredService<MainWindow>();
        window.Show();
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        if (_host is not null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }
        base.OnExit(e);
    }
}
