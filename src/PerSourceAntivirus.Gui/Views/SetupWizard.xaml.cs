using System.ServiceProcess;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using WpfButton = System.Windows.Controls.Button;
using WpfCheckBox = System.Windows.Controls.CheckBox;
using WpfTextBox = System.Windows.Controls.TextBox;

namespace PerSourceAntivirus.Gui.Views;

public partial class SetupWizard : Window
{
    private int _step = 1;
    private const int TotalSteps = 5;

    private string _yaraDirectory = string.Empty;
    private bool _realtimeEnabled = true;
    private string _exclusionPaths = string.Empty;

    public int CurrentStep => _step;

    public SetupWizard()
    {
        InitializeComponent();
        DataContext = this;
        UpdateStepContent();
    }

    public static bool ShouldShowOnStartup()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\PerSourceAntivirus");
            return key?.GetValue("SetupComplete") == null;
        }
        catch { return false; }
    }

    public static void MarkSetupComplete()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(@"Software\PerSourceAntivirus", true);
            key.SetValue("SetupComplete", "1", RegistryValueKind.String);
        }
        catch { }
    }

    private void UpdateStepContent()
    {
        StepContent.Content = _step switch
        {
            1 => BuildStep1(),
            2 => BuildStep2(),
            3 => BuildStep3(),
            4 => BuildStep4(),
            5 => BuildStep5(),
            _ => null
        };

        BtnPrev.IsEnabled = _step > 1;
        BtnNext.Visibility = _step < TotalSteps ? Visibility.Visible : Visibility.Collapsed;
        BtnFinish.Visibility = _step == TotalSteps ? Visibility.Visible : Visibility.Collapsed;
    }

    private UIElement BuildStep1()
    {
        var panel = new StackPanel { Margin = new Thickness(0) };
        panel.Children.Add(new TextBlock
        {
            Text = "Welcome to PerSource Antivirus",
            FontSize = 20, FontWeight = FontWeights.Bold,
            Foreground = System.Windows.Media.Brushes.Black,
            Margin = new Thickness(0, 0, 0, 12)
        });
        panel.Children.Add(new TextBlock
        {
            Text = "This wizard will help you configure PerSource Antivirus for optimal protection.",
            FontSize = 13, TextWrapping = TextWrapping.Wrap,
            Foreground = System.Windows.Media.Brushes.DimGray,
            Margin = new Thickness(0, 0, 0, 20)
        });

        var driverStatus = CheckDriverStatus();
        var statusColor = driverStatus ? System.Windows.Media.Brushes.Green : System.Windows.Media.Brushes.OrangeRed;
        var statusText = driverStatus ? "Driver service 'PerSourceAV' is running." : "Driver service 'PerSourceAV' not found. Install the driver for full protection.";
        panel.Children.Add(new Border
        {
            Background = driverStatus ? System.Windows.Media.Brushes.LightGreen : System.Windows.Media.Brushes.MistyRose,
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(12, 8, 12, 8),
            Child = new TextBlock
            {
                Text = statusText, FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Foreground = statusColor
            }
        });
        return panel;
    }

    private UIElement BuildStep2()
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock
        {
            Text = "YARA Rules Directory",
            FontSize = 18, FontWeight = FontWeights.Bold,
            Foreground = System.Windows.Media.Brushes.Black,
            Margin = new Thickness(0, 0, 0, 12)
        });
        panel.Children.Add(new TextBlock
        {
            Text = "Select the directory containing your YARA rule files (.yar, .yara).",
            FontSize = 13, TextWrapping = TextWrapping.Wrap,
            Foreground = System.Windows.Media.Brushes.DimGray,
            Margin = new Thickness(0, 0, 0, 16)
        });

        var txtPath = new WpfTextBox
        {
            Text = _yaraDirectory, Padding = new Thickness(8, 6, 8, 6),
            FontSize = 13
        };
        txtPath.TextChanged += (_, _) => _yaraDirectory = txtPath.Text;

        var btnBrowse = new WpfButton
        {
            Content = "Browse...", Padding = new Thickness(12, 6, 12, 6),
            Margin = new Thickness(0, 8, 0, 0),
            Cursor = System.Windows.Input.Cursors.Hand
        };
        btnBrowse.Click += (_, _) =>
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "Select YARA Rules Directory",
                SelectedPath = _yaraDirectory
            };
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                _yaraDirectory = dialog.SelectedPath;
                txtPath.Text = _yaraDirectory;
            }
        };

        panel.Children.Add(txtPath);
        panel.Children.Add(btnBrowse);
        return panel;
    }

    private UIElement BuildStep3()
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock
        {
            Text = "Real-Time Protection",
            FontSize = 18, FontWeight = FontWeights.Bold,
            Foreground = System.Windows.Media.Brushes.Black,
            Margin = new Thickness(0, 0, 0, 12)
        });
        panel.Children.Add(new TextBlock
        {
            Text = "Real-time protection monitors file system activity and blocks threats automatically.",
            FontSize = 13, TextWrapping = TextWrapping.Wrap,
            Foreground = System.Windows.Media.Brushes.DimGray,
            Margin = new Thickness(0, 0, 0, 16)
        });

        var chk = new WpfCheckBox
        {
            Content = "Enable Real-Time Protection",
            IsChecked = _realtimeEnabled, FontSize = 14
        };
        chk.Checked += (_, _) => _realtimeEnabled = true;
        chk.Unchecked += (_, _) => _realtimeEnabled = false;
        panel.Children.Add(chk);
        return panel;
    }

    private UIElement BuildStep4()
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock
        {
            Text = "Configure Exclusions",
            FontSize = 18, FontWeight = FontWeights.Bold,
            Foreground = System.Windows.Media.Brushes.Black,
            Margin = new Thickness(0, 0, 0, 12)
        });
        panel.Children.Add(new TextBlock
        {
            Text = "Enter paths to exclude from scanning (one per line).",
            FontSize = 13, TextWrapping = TextWrapping.Wrap,
            Foreground = System.Windows.Media.Brushes.DimGray,
            Margin = new Thickness(0, 0, 0, 12)
        });

        var txt = new WpfTextBox
        {
            Text = _exclusionPaths,
            AcceptsReturn = true, MinLines = 6, MaxLines = 10,
            Padding = new Thickness(8, 6, 8, 6), FontSize = 13,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };
        txt.TextChanged += (_, _) => _exclusionPaths = txt.Text;
        panel.Children.Add(txt);
        return panel;
    }

    private UIElement BuildStep5()
    {
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock
        {
            Text = "Setup Complete",
            FontSize = 20, FontWeight = FontWeights.Bold,
            Foreground = System.Windows.Media.Brushes.Black,
            Margin = new Thickness(0, 0, 0, 16)
        });

        var summary = $"Configuration Summary:\n\n" +
                      $"YARA Rules: {(_yaraDirectory.Length > 0 ? _yaraDirectory : "(not set)")}\n" +
                      $"Real-Time Protection: {(_realtimeEnabled ? "Enabled" : "Disabled")}\n" +
                      $"Exclusions: {(_exclusionPaths.Trim().Length > 0 ? _exclusionPaths.Trim().Split('\n').Length + " entries" : "none")}";

        panel.Children.Add(new TextBlock
        {
            Text = summary, FontSize = 13,
            Foreground = System.Windows.Media.Brushes.DimGray,
            TextWrapping = TextWrapping.Wrap
        });
        return panel;
    }

    private static bool CheckDriverStatus()
    {
        try
        {
            var services = ServiceController.GetServices();
            return services.Any(s => s.ServiceName.Equals("PerSourceAV", StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }

    private void BtnNext_Click(object sender, RoutedEventArgs e)
    {
        if (_step < TotalSteps)
        {
            _step++;
            Notify(nameof(CurrentStep));
            UpdateStepContent();
        }
    }

    private void BtnPrev_Click(object sender, RoutedEventArgs e)
    {
        if (_step > 1)
        {
            _step--;
            Notify(nameof(CurrentStep));
            UpdateStepContent();
        }
    }

    private void BtnFinish_Click(object sender, RoutedEventArgs e)
    {
        MarkSetupComplete();
        DialogResult = true;
        Close();
    }

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    private void Notify(string name) =>
        PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
}

