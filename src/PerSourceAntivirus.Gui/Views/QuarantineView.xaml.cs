using System.Globalization;
using System.Windows.Controls;
using System.Windows.Data;
using PerSourceAntivirus.Gui.ViewModels;

namespace PerSourceAntivirus.Gui.Views;

public partial class QuarantineView
{
    public QuarantineView() => InitializeComponent();

    private async void OnRestoreClick(object sender, System.Windows.RoutedEventArgs e)
    {
        if (DataContext is QuarantineViewModel vm)
            await vm.RestoreSelectedAsync();
    }
}

public class NullToBoolConverter : IValueConverter
{
    public static readonly NullToBoolConverter Instance = new();
    public object Convert(object? value, Type t, object? p, CultureInfo c) => value is not null;
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotImplementedException();
}
