namespace PerSourceAntivirus.Application.Network.Commands.StartNetworkCapture;

public record StartNetworkCaptureResult(int PacketsCaptured, int BlocklistedCount, TimeSpan Duration);
