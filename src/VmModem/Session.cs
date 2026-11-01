namespace VmModem;

/// <summary>
/// One "serial cable" connection (a named pipe client/server instance or a TCP
/// socket) with its own modem, event loop and NAT. Run() blocks until the cable
/// is unplugged (VM powered off, pipe closed, ...).
/// </summary>
public sealed class Session
{
    readonly Stream _stream;
    readonly Options _opt;
    readonly string _name;

    public EventLoop Loop { get; } = new();
    public SerialOut Out { get; }

    public Session(Stream stream, Options opt, string name)
    {
        _stream = stream;
        _opt = opt;
        _name = name;
        Out = new SerialOut(stream, opt.Baud);
    }

    public void Run()
    {
        Log.Info($"[{_name}] serial line connected");
        var modem = new Modem(this, _opt);
        Out.Failed += ex => { Log.Debug($"[{_name}] write failed: {ex.Message}"); Loop.Stop(); };

        var reader = Task.Run(async () =>
        {
            var buf = new byte[4096];
            try
            {
                while (true)
                {
                    int n = await _stream.ReadAsync(buf, Loop.Stopping);
                    if (n == 0) break;
                    var chunk = buf[..n];
                    long now = Environment.TickCount64;
                    Log.Hex($"[{_name}] VM -> modem", chunk);
                    Loop.Post(() => modem.OnSerialData(chunk, now));
                }
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException or InvalidOperationException)
            {
            }
            Loop.Stop();
        });

        using (Loop.Every(TimeSpan.FromMilliseconds(100), modem.Tick))
        {
            Loop.Run();
        }

        modem.Shutdown();
        Out.Dispose();
        try { _stream.Dispose(); } catch (Exception) { }
        reader.Wait(TimeSpan.FromSeconds(2));
        Log.Info($"[{_name}] serial line disconnected");
    }
}
