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

    // [AUDIT FIX — HIGH, Domain 1 Fail Loudly / Domain 16] async void event overrides can't be
    // awaited by the caller, so any exception escaping the body becomes unhandled on the
    // dispatcher and crashes the process with no visible error (documented as known debt in
    // CLAUDE.md item 5 for two prior sessions). The entire startup sequence is now one
    // try/catch: on failure the user sees a MessageBox instead of a silent crash, and the app
    // shuts down cleanly instead of leaving a half-started host/tray icon behind.
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        try
        {
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
                    services.AddSingleton<ThemeManager>();
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

            var themeManager = _host.Services.GetRequiredService<ThemeManager>();
            var configuration = _host.Services.GetRequiredService<IConfiguration>();
            themeManager.ApplyTheme(configuration["Gui:Theme"] ?? ThemeManager.Light);

            _tray = _host.Services.GetRequiredService<TrayIconService>();
            _tray.Initialize();

            var window = _host.Services.GetRequiredService<MainWindow>();
            window.Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Falha ao iniciar o PerSourceAntivirus:\n\n{ex.Message}",
                "Erro de inicialização",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(-1);
        }
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        try
        {
            _tray?.Dispose();
            if (_host is not null)
            {
                await _host.StopAsync();
                _host.Dispose();
            }
        }
        catch { /* shutting down anyway — never let this prevent process exit */ }
        base.OnExit(e);
    }
}
