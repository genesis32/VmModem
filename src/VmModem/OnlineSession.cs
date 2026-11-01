using System.Text;
using VmModem.Link;
using VmModem.Net;

namespace VmModem;

/// <summary>
/// What sits on the "far end" of the phone line once the modem has connected:
/// a small terminal-server style login dialog (like an old ISP), then PPP or SLIP,
/// feeding a NAT stack. PPP frames (0x7E) or SLIP frames (0xC0) are auto-detected
/// at any point during the text dialog.
/// </summary>
public sealed class OnlineSession : IDisposable
{
    enum Mode { Username, Password, Prompt, Link }

    readonly Session _session;
    readonly Options _opt;
    readonly Func<byte[], long> _send;
    readonly Action<string> _hangup;
    readonly StringBuilder _line = new();
    readonly NatStack _nat;
    ILink? _link;
    Mode _mode;
    string _user = "";
    bool _disposed;

    public OnlineSession(Session session, Options opt, Func<byte[], long> send, Action<string> hangup)
    {
        _session = session;
        _opt = opt;
        _send = send;
        _hangup = hangup;
        _nat = new NatStack(session.Loop, opt, session.Out);
    }

    public void Start()
    {
        switch (_opt.Session)
        {
            case SessionMode.Ppp: StartLink(ppp: true); break;
            case SessionMode.Slip: StartLink(ppp: false); break;
            default:
                _mode = Mode.Username;
                Text("\r\n\r\nVmModem dial-up access server\r\n\r\nUsername: ");
                break;
        }
    }

    void Text(string s) => _send(Encoding.ASCII.GetBytes(s));

    public void OnData(byte[] data, int offset, int count)
    {
        if (_disposed) return;
        if (_link != null) { _link.OnData(data, offset, count); return; }

        int end = offset + count;
        for (int i = offset; i < end; i++)
        {
            byte b = data[i];
            if (b == Hdlc.Flag || b == SlipLink.End)
            {
                Log.Debug($"Detected {(b == Hdlc.Flag ? "PPP" : "SLIP")} frames from guest");
                StartLink(ppp: b == Hdlc.Flag, detected: true);
                _link!.OnData(data, i, end - i);
                return;
            }
            TextByte(b);
            if (_disposed || _link != null)
            {
                // A command switched modes (or hung up) mid-buffer: pass the rest along.
                if (_link != null && i + 1 < end) _link.OnData(data, i + 1, end - i - 1);
                return;
            }
        }
    }

    void TextByte(byte b)
    {
        if (b == '\r')
        {
            Text("\r\n");
            string line = _line.ToString().Trim();
            _line.Clear();
            OnLine(line);
            return;
        }
        if (b == '\n') return;
        if (b == 8 || b == 0x7F)
        {
            if (_line.Length > 0) { _line.Length--; if (_mode != Mode.Password) Text("\b \b"); }
            return;
        }
        if (b < 0x20 || b > 0x7E || _line.Length >= 128) return;
        _line.Append((char)b);
        if (_mode != Mode.Password) _send(new[] { b });
    }

    void OnLine(string line)
    {
        switch (_mode)
        {
            case Mode.Username:
                _user = line;
                _mode = Mode.Password;
                Text("Password: ");
                break;
            case Mode.Password:
                Log.Info($"Terminal login '{_user}' accepted");
                _mode = Mode.Prompt;
                Text($"\r\nWelcome, {(_user.Length > 0 ? _user : "guest")}. Type 'ppp' or 'slip' to start, 'help' for commands.\r\n\r\n");
                Prompt();
                break;
            case Mode.Prompt:
                Command(line);
                break;
        }
    }

    void Prompt() => Text($"{_opt.Hostname}> ");

    string AddressInfo(int mtu) =>
        $"Your IP address is {_opt.GuestIp}\r\n" +
        $"Gateway is {_opt.GatewayIp}, DNS server is {_opt.DnsIp}, netmask {_opt.Netmask}\r\n" +
        $"MTU is {mtu} bytes\r\n";

    void Command(string line)
    {
        string cmd = line.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.ToLowerInvariant() ?? "";
        switch (cmd)
        {
            case "":
                break;
            case "ppp":
                Text("Entering PPP mode.\r\n" + AddressInfo(1500));
                StartLink(ppp: true);
                return;
            case "slip":
                Text("Entering SLIP mode.\r\n" + AddressInfo(SlipLink.DefaultMtu));
                StartLink(ppp: false);
                return;
            case "cslip":
                Text("CSLIP (Van Jacobson compression) is not supported. Use 'slip' and turn off VJ compression.\r\n");
                break;
            case "ip": case "show":
                Text(AddressInfo(1500));
                break;
            case "help": case "?":
                Text("Commands:\r\n" +
                     "  ppp     start PPP (also starts automatically when PPP frames arrive)\r\n" +
                     "  slip    start SLIP\r\n" +
                     "  ip      show network settings\r\n" +
                     "  logout  hang up\r\n");
                break;
            case "logout": case "exit": case "quit": case "bye": case "hangup":
                Text("Goodbye.\r\n");
                _session.Loop.Schedule(TimeSpan.FromMilliseconds(300), () => _hangup("logout"));
                _mode = Mode.Link; // ignore further text
                return;
            default:
                Text($"Unknown command '{cmd}'. Type 'help'.\r\n");
                break;
        }
        Prompt();
    }

    /// <param name="detected">The VM's own frames triggered this, so it's already listening for PPP.</param>
    void StartLink(bool ppp, bool detected = false)
    {
        _mode = Mode.Link;
        _link = ppp
            ? new PppLink(_session.Loop, _opt, _send, _nat.OnIpPacket, ip => _nat.GuestIp = ip, _hangup) { PeerAlreadyActive = detected }
            : new SlipLink(_send, _nat.OnIpPacket);
        _nat.Attach(_link);
        _link.Start();
    }

    public void Tick()
    {
        if (_disposed) return;
        _link?.Tick();
        _nat.Tick();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _link?.Dispose();
        _nat.Dispose();
        _nat.LogStats();
    }
}
