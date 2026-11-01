using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using VmModem;
using VmModem.Net;

Options? opt;
try
{
    opt = Options.Parse(args);
}
catch (Exception ex) when (ex is ArgumentException or FormatException)
{
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine("Use --help for usage.");
    return 1;
}
if (opt == null) return 0;

if (opt.LogFile != null)
{
    try { Log.OpenFile(opt.LogFile); }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"Can't open log file {opt.LogFile}: {ex.Message}");
        return 1;
    }
}

AppDomain.CurrentDomain.UnhandledException += (_, e) => Log.Error($"Unhandled exception: {e.ExceptionObject}");

Console.Title = "VmModem";
Log.Info("VmModem - virtual 56k modem / dial-up ISP");
Log.Info($"Console log level: {Log.Level}. Log file: {Log.FilePath ?? "(disabled)"}");
Log.Debug($"Command line: {Environment.CommandLine}");
Log.Info($"Line speed: {(opt.Baud > 0 ? $"{opt.Baud} bps" : "unlimited")}, session: {opt.Session}, auth: {opt.Auth}");
Log.Info($"Guest network: IP {opt.GuestIp}, mask {opt.Netmask}, gateway {opt.GatewayIp}, DNS {opt.DnsIp}" +
         (opt.AllowHostLoopback ? $" ({opt.GatewayIp} = this PC's 127.0.0.1)" : ""));
var dns = opt.DnsServers.Count > 0 ? opt.DnsServers : DnsForwarder.DiscoverHostDnsServers();
Log.Info($"Upstream DNS: {(dns.Count > 0 ? string.Join(", ", dns) : "system resolver")}");

using var quit = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; quit.Cancel(); };

var workers = new List<Thread>();
if (opt.PipeName != null)
{
    var t = new Thread(() => (opt.PipeConnect ? (Action<Options, CancellationToken>)PipeClientLoop : PipeServerLoop)(opt, quit.Token))
        { IsBackground = true, Name = "Pipe" };
    t.Start();
    workers.Add(t);
}
if (opt.TcpPort is int port)
{
    var t = new Thread(() => TcpLoop(opt, port, quit.Token)) { IsBackground = true, Name = "Tcp" };
    t.Start();
    workers.Add(t);
}

Log.Info("Press Ctrl+C to quit.");
quit.Token.WaitHandle.WaitOne();
Log.Info("Shutting down.");
return 0;

static void PipeServerLoop(Options opt, CancellationToken quit)
{
    while (!quit.IsCancellationRequested)
    {
        NamedPipeServerStream pipe;
        try
        {
            pipe = new NamedPipeServerStream(opt.PipeShortName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 65536, 65536);
        }
        catch (IOException ex)
        {
            Log.Error($"Can't create {opt.PipePath}: {ex.Message} (is another program - or the VM - already serving it? " +
                      "If the VM creates the pipe, run with --connect)");
            if (quit.WaitHandle.WaitOne(5000)) return;
            continue;
        }
        Log.Info($"Waiting for the VM to open {opt.PipePath} ...");
        try
        {
            pipe.WaitForConnectionAsync(quit).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) { pipe.Dispose(); return; }
        catch (IOException ex) { Log.Warn($"Pipe error: {ex.Message}"); pipe.Dispose(); continue; }

        new Session(pipe, opt, "pipe").Run();
    }
}

static void PipeClientLoop(Options opt, CancellationToken quit)
{
    bool announced = false;
    string server = ".";
    string name = opt.PipeShortName;
    // Allow \\host\pipe\name
    if (opt.PipePath.StartsWith(@"\\", StringComparison.Ordinal) && !opt.PipePath.StartsWith(@"\\.\", StringComparison.Ordinal))
    {
        var parts = opt.PipePath.TrimStart('\\').Split('\\', 3);
        if (parts.Length == 3) { server = parts[0]; name = parts[2]; }
    }

    while (!quit.IsCancellationRequested)
    {
        var pipe = new NamedPipeClientStream(server, name, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            if (!announced) { Log.Info($"Connecting to {opt.PipePath} (waiting for the VM to start) ..."); announced = true; }
            pipe.Connect(1000);
        }
        catch (TimeoutException) { pipe.Dispose(); if (quit.WaitHandle.WaitOne(1000)) return; continue; }
        catch (UnauthorizedAccessException)
        {
            pipe.Dispose();
            Log.Error($"Access denied opening {opt.PipePath}. Hyper-V pipes require running VmModem as Administrator.");
            if (quit.WaitHandle.WaitOne(5000)) return;
            continue;
        }
        catch (IOException ex)
        {
            pipe.Dispose();
            Log.Debug($"Pipe connect failed: {ex.Message}");
            if (quit.WaitHandle.WaitOne(2000)) return;
            continue;
        }

        new Session(pipe, opt, "pipe").Run();
        announced = false;
        if (quit.WaitHandle.WaitOne(1000)) return;
    }
}

static void TcpLoop(Options opt, int port, CancellationToken quit)
{
    var listener = new TcpListener(IPAddress.Loopback, port);
    try { listener.Start(); }
    catch (SocketException ex) { Log.Error($"Can't listen on TCP port {port}: {ex.SocketErrorCode}"); return; }
    Log.Info($"Also accepting raw serial connections on 127.0.0.1:{port}");
    quit.Register(listener.Stop);
    while (!quit.IsCancellationRequested)
    {
        TcpClient client;
        try { client = listener.AcceptTcpClient(); }
        catch (SocketException) { return; }
        catch (ObjectDisposedException) { return; }
        client.NoDelay = true;
        var name = $"tcp {client.Client.RemoteEndPoint}";
        new Thread(() => { using (client) new Session(client.GetStream(), opt, name).Run(); })
            { IsBackground = true, Name = name }.Start();
    }
}
