using System.Windows.Input;
using MediatR;

namespace PerSourceAntivirus.Gui.ViewModels;

public class MainViewModel : ViewModelBase
{
    private readonly IMediator _mediator;
    private ViewModelBase? _currentView;
    private string _activeNav = "Dashboard";

    public ViewModelBase? CurrentView { get => _currentView; private set => Set(ref _currentView, value); }
    public string ActiveNav { get => _activeNav; private set => Set(ref _activeNav, value); }

    public DashboardViewModel    Dashboard    { get; }
    public ThreatsViewModel      Threats      { get; }
    public QuarantineViewModel   Quarantine   { get; }
    public AlertsViewModel       Alerts       { get; }
    public NotificationsViewModel Notifications { get; }
    public SettingsViewModel     Settings     { get; }
    public ExclusionsViewModel   Exclusions   { get; }
    public ScanProfilesViewModel ScanProfiles { get; }
    public ReportsViewModel      Reports      { get; }
    public SystemStatusViewModel SystemStatus { get; }
    public TimelineViewModel     Timeline     { get; }
    public HuntViewModel         Hunt         { get; }

    public ICommand ShowDashboardCommand    { get; }
    public ICommand ShowThreatsCommand      { get; }
    public ICommand ShowQuarantineCommand   { get; }
    public ICommand ShowAlertsCommand       { get; }
    public ICommand ShowNotificationsCommand { get; }
    public ICommand ShowSettingsCommand     { get; }
    public ICommand ShowExclusionsCommand   { get; }
    public ICommand ShowScanProfilesCommand { get; }
    public ICommand ShowReportsCommand      { get; }
    public ICommand ShowSystemStatusCommand { get; }
    public ICommand ShowTimelineCommand     { get; }
    public ICommand ShowHuntCommand         { get; }

    public MainViewModel(IMediator mediator,
        DashboardViewModel    dashboard,
        ThreatsViewModel      threats,
        QuarantineViewModel   quarantine,
        AlertsViewModel       alerts,
        NotificationsViewModel notifications,
        SettingsViewModel     settings,
        ExclusionsViewModel   exclusions,
        ScanProfilesViewModel scanProfiles,
        ReportsViewModel      reports,
        SystemStatusViewModel systemStatus,
        TimelineViewModel     timeline,
        HuntViewModel         hunt)
    {
        _mediator     = mediator;
        Dashboard     = dashboard;
        Threats       = threats;
        Quarantine    = quarantine;
        Alerts        = alerts;
        Notifications = notifications;
        Settings      = settings;
        Exclusions    = exclusions;
        ScanProfiles  = scanProfiles;
        Reports       = reports;
        SystemStatus  = systemStatus;
        Timeline      = timeline;
        Hunt          = hunt;

        ShowDashboardCommand    = new RelayCommand(() => Navigate("Dashboard",    Dashboard));
        ShowThreatsCommand      = new RelayCommand(() => Navigate("Threats",      Threats));
        ShowQuarantineCommand   = new RelayCommand(() => Navigate("Quarantine",   Quarantine));
        ShowAlertsCommand       = new RelayCommand(() => Navigate("Alerts",       Alerts));
        ShowNotificationsCommand = new RelayCommand(() => Navigate("Notifications", Notifications));
        ShowSettingsCommand     = new RelayCommand(() => Navigate("Settings",     Settings));
        ShowExclusionsCommand   = new RelayCommand(() => Navigate("Exclusions",   Exclusions));
        ShowScanProfilesCommand = new RelayCommand(() => Navigate("ScanProfiles", ScanProfiles));
        ShowReportsCommand      = new RelayCommand(() => Navigate("Reports",      Reports));
        ShowSystemStatusCommand = new RelayCommand(() => Navigate("SystemStatus", SystemStatus));
        ShowTimelineCommand     = new RelayCommand(() => Navigate("Timeline",     Timeline));
        ShowHuntCommand         = new RelayCommand(() => Navigate("Hunt",         Hunt));

        CurrentView = Dashboard;
    }

    private void Navigate(string name, ViewModelBase vm)
    {
        ActiveNav   = name;
        CurrentView = vm;
        Notify(nameof(IsDashboardActive));
        Notify(nameof(IsThreatsActive));
        Notify(nameof(IsQuarantineActive));
        Notify(nameof(IsAlertsActive));
        Notify(nameof(IsNotificationsActive));
        Notify(nameof(IsSettingsActive));
        Notify(nameof(IsExclusionsActive));
        Notify(nameof(IsScanProfilesActive));
        Notify(nameof(IsReportsActive));
        Notify(nameof(IsSystemStatusActive));
        Notify(nameof(IsTimelineActive));
        Notify(nameof(IsHuntActive));
    }

    public bool IsDashboardActive    => ActiveNav == "Dashboard";
    public bool IsThreatsActive      => ActiveNav == "Threats";
    public bool IsQuarantineActive   => ActiveNav == "Quarantine";
    public bool IsAlertsActive       => ActiveNav == "Alerts";
    public bool IsNotificationsActive => ActiveNav == "Notifications";
    public bool IsSettingsActive     => ActiveNav == "Settings";
    public bool IsExclusionsActive   => ActiveNav == "Exclusions";
    public bool IsScanProfilesActive => ActiveNav == "ScanProfiles";
    public bool IsReportsActive      => ActiveNav == "Reports";
    public bool IsSystemStatusActive => ActiveNav == "SystemStatus";
    public bool IsTimelineActive     => ActiveNav == "Timeline";
    public bool IsHuntActive         => ActiveNav == "Hunt";
}

public class RelayCommand(Action execute, Func<bool>? canExecute = null) : ICommand
{
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => canExecute?.Invoke() ?? true;
    public void Execute(object? parameter) => execute();
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
