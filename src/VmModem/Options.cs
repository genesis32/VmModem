using System.Net;

namespace VmModem;

public enum SessionMode { Login, Ppp, Slip }
public enum AuthMode { None, Pap, Chap }

public sealed class Options
{
    public string? PipeName { get; set; } = "vmmodem";
    public bool PipeConnect { get; set; }
    public int? TcpPort { get; set; }
    public int Baud { get; set; } = 56000;
    public SessionMode Session { get; set; } = SessionMode.Login;
    public AuthMode Auth { get; set; } = AuthMode.None;
    public int DialDelayMs { get; set; } = 2000;
    public bool AllowHostLoopback { get; set; } = true;
    public List<IPAddress> DnsServers { get; } = new();
    public string Hostname { get; set; } = "vmmodem";
    public string? LogFile { get; set; } = Log.DefaultFilePath;

    // Virtual network as seen from inside the VM.
    public IPAddress GuestIp { get; set; } = IPAddress.Parse("10.0.2.15");
    public IPAddress GatewayIp { get; set; } = IPAddress.Parse("10.0.2.2");
    public IPAddress DnsIp { get; set; } = IPAddress.Parse("10.0.2.3");
    public IPAddress Netmask { get; set; } = IPAddress.Parse("255.255.255.0");

    public string PipePath =>
        PipeName is null ? "" :
        PipeName.StartsWith(@"\\", StringComparison.Ordinal) ? PipeName : @"\\.\pipe\" + PipeName;

    /// <summary>Name as expected by NamedPipe*Stream (without the \\.\pipe\ prefix).</summary>
    public string PipeShortName
    {
        get
        {
            var p = PipePath;
            const string prefix = @"\\.\pipe\";
            return p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? p[prefix.Length..] : p;
        }
    }

    public static void PrintUsage()
    {
        Console.WriteLine("""
            VmModem - a virtual Hayes 56k modem on a named pipe, with a built-in
                      PPP/SLIP dial-up "ISP" that NATs the VM onto the host's internet.

            Usage: VmModem [options]

              -p, --pipe <name>       Pipe name or full path (default: vmmodem = \\.\pipe\vmmodem)
              -c, --connect           Connect to a pipe the VM created instead of creating it.
                                      Use for Hyper-V, VirtualBox (default "Host Pipe" mode),
                                      VMware ("This end is the server") and QEMU -serial pipe:.
                  --no-pipe           Don't use a named pipe (use with --tcp).
              -t, --tcp <port>        Also accept connections on 127.0.0.1:<port> (raw TCP serial,
                                      e.g. DOSBox nullmodem, QEMU -serial tcp:, 86Box, testing).
              -b, --baud <bps>        Throttle VM-bound data to this line rate (default 56000,
                                      0 = unlimited). Protects slow emulated UARTs from overruns.
                  --session <mode>    What happens after CONNECT:
                                        login (default) Username/Password prompts and a ">" prompt
                                                        accepting "ppp" / "slip"; PPP is also
                                                        auto-detected at any time.
                                        ppp             go straight to PPP
                                        slip            go straight to SLIP (no text at all)
                  --auth <none|pap|chap>  Ask the PPP client to authenticate (any login accepted).
                  --dns <ip>          Upstream DNS server (repeatable). Default: host's DNS servers.
                  --guest-ip <ip>     Address assigned to the VM (default 10.0.2.15)
                  --dial-delay <ms>   Fake dialing time before CONNECT (default 2000)
                  --no-loopback       Don't map 10.0.2.2 to the host's 127.0.0.1
              -v, --verbose           Debug detail: PPP negotiation, every connection, dropped packets
              -vv                     ...plus every IP packet
              -vvv                    ...plus a hex dump of all serial data in both directions
                  --log <file>        Log file (default %LOCALAPPDATA%\VmModem\vmmodem.log). The file always
                                      gets every packet (-vv detail); hex dumps only with -vvv.
                  --no-log            Don't write a log file
              -h, --help              Show this help

            Network inside the VM:  IP 10.0.2.15  mask 255.255.255.0  gateway 10.0.2.2  DNS 10.0.2.3
            """);
    }

    /// <summary>Parses command line arguments. Returns null if the program should exit.</summary>
    public static Options? Parse(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string Next()
            {
                if (i + 1 >= args.Length) throw new ArgumentException($"Missing value for {a}");
                return args[++i];
            }
            switch (a.ToLowerInvariant())
            {
                case "-h": case "--help": case "/?": case "-?":
                    PrintUsage(); return null;
                case "-p": case "--pipe": o.PipeName = Next(); break;
                case "-c": case "--connect": o.PipeConnect = true; break;
                case "--no-pipe": o.PipeName = null; break;
                case "-t": case "--tcp": o.TcpPort = int.Parse(Next()); break;
                case "-b": case "--baud": o.Baud = int.Parse(Next()); break;
                case "--session":
                    o.Session = Enum.Parse<SessionMode>(Next(), ignoreCase: true); break;
                case "--auth":
                    o.Auth = Enum.Parse<AuthMode>(Next(), ignoreCase: true); break;
                case "--dns": o.DnsServers.Add(IPAddress.Parse(Next())); break;
                case "--guest-ip": o.GuestIp = IPAddress.Parse(Next()); break;
                case "--dial-delay": o.DialDelayMs = int.Parse(Next()); break;
                case "--no-loopback": o.AllowHostLoopback = false; break;
                case "-v": case "--verbose": o.BumpVerbosity(1); break;
                case "-vv": o.BumpVerbosity(2); break;
                case "-vvv": o.BumpVerbosity(3); break;
                case "--log": o.LogFile = Next(); break;
                case "--no-log": o.LogFile = null; break;
                default: throw new ArgumentException($"Unknown option: {a}");
            }
        }
        if (o.PipeName is null && o.TcpPort is null)
            throw new ArgumentException("Nothing to listen on: --no-pipe requires --tcp <port>");
        return o;
    }

    void BumpVerbosity(int n) => Log.Level = (LogLevel)Math.Min((int)LogLevel.Dump, (int)Log.Level + n);
}
