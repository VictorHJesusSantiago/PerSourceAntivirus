using System.Windows;

namespace PerSourceAntivirus.Gui.Services;

public sealed class ThemeManager
{
    public const string Light = "Light";
    public const string Dark = "Dark";

    public string CurrentTheme { get; private set; } = Light;

    public void ApplyTheme(string themeName)
    {
        var normalized = themeName.Equals(Dark, StringComparison.OrdinalIgnoreCase) ? Dark : Light;
        var uri = new Uri($"Themes/{normalized}Theme.xaml", UriKind.Relative);
        var newDictionary = new ResourceDictionary { Source = uri };

        var app = System.Windows.Application.Current;
        var merged = app.Resources.MergedDictionaries;

        var previous = merged.FirstOrDefault(d =>
            d.Source is not null && d.Source.OriginalString.Contains("Theme.xaml", StringComparison.OrdinalIgnoreCase));
        if (previous is not null) merged.Remove(previous);

        merged.Add(newDictionary);
        CurrentTheme = normalized;
    }
}
