namespace PerSourceAntivirus.Application.Common.Interfaces;

// "Gamer mode": true when the foreground window exactly covers a monitor (exclusive
// fullscreen), so the GUI can suppress toast notifications while the user is gaming/presenting.
public interface IFullScreenDetector
{
    bool IsFullScreenAppActive();
}
