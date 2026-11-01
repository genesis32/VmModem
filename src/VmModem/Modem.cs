using System.Text;

namespace VmModem;

/// <summary>
/// Hayes-compatible modem emulation: AT command mode, fake dialing, CONNECT,
/// "+++" escape with guard time, ATO / ATH. Once connected, data is handed to an
/// <see cref="OnlineSession"/> (terminal server + PPP/SLIP + NAT).
/// All methods run on the session's event loop thread.
/// </summary>
public sealed class Modem
{
    enum State { Command, Dialing, Online, OnlineCommand }

    readonly Session _session;
    readonly Options _opt;
    readonly byte[] _reg = new byte[256];
    readonly StringBuilder _line = new();
    readonly List<byte> _echoBuf = new();

    State _state = State.Command;
    bool _echo, _verbose, _quiet;
    int _x;
    int _selectedReg;
    string _lastCmd = "";
    string _dialed = "";
    OnlineSession? _online;
    IDisposable? _dialTimer;
    IDisposable? _escapeTimer;
    long _lastRxMs;
    int _plusCount;
    bool _discarding;
    long _lastCmdRxMs;
    long _lastFrameWarnMs = long.MinValue / 2;

    public Modem(Session session, Options opt)
    {
        _session = session;
        _opt = opt;
        ResetSettings();
    }

    public bool IsOnline => _state == State.Online;

    void ResetSettings()
    {
        _echo = true; _verbose = true; _quiet = false; _x = 4; _selectedReg = 0;
        Array.Clear(_reg);
        _reg[2] = (byte)'+';  // escape character
        _reg[3] = 13;         // CR
        _reg[4] = 10;         // LF
        _reg[5] = 8;          // backspace
        _reg[6] = 2;          // wait for dial tone
        _reg[7] = 50;         // wait for carrier
        _reg[8] = 2;          // comma pause
        _reg[10] = 14;        // carrier loss delay
        _reg[12] = 50;        // escape guard time, 1/50 s
    }

    // ---- input ---------------------------------------------------------------------------

    public void OnSerialData(byte[] data, long nowMs)
    {
        int i = 0;
        while (i < data.Length)
        {
            switch (_state)
            {
                case State.Online:
                    // Everything goes to the online session; just watch for "+++".
                    TrackEscape(data.AsSpan(i), nowMs);
                    _online!.OnData(data, i, data.Length - i);
                    i = data.Length;
                    break;

                case State.Dialing:
                    // Any keypress aborts dialing, like a real modem (stray LF after the CR doesn't count).
                    if (data[i] < 0x20) { i++; break; }
                    _dialTimer?.Dispose();
                    _dialTimer = null;
                    _state = State.Command;
                    Log.Info("Dial aborted by DTE");
                    Respond("NO CARRIER", 3);
                    i++;
                    break;

                default:
                    CommandByte(data[i++], nowMs);
                    break;
            }
        }
        FlushEcho();
    }

    void TrackEscape(ReadOnlySpan<byte> data, long nowMs)
    {
        long guard = _reg[12] * 20L;
        if (guard == 0) return;
        foreach (byte b in data)
        {
            if (b == _reg[2])
            {
                if (_plusCount > 0) _plusCount++;
                else if (nowMs - _lastRxMs >= guard) _plusCount = 1;
            }
            else _plusCount = 0;
            if (_plusCount > 3) _plusCount = 0;
            _lastRxMs = nowMs;
        }
        if (_plusCount == 3)
        {
            _escapeTimer?.Dispose();
            _escapeTimer = _session.Loop.Schedule(TimeSpan.FromMilliseconds(guard), () =>
            {
                if (_state == State.Online && _plusCount == 3 && Environment.TickCount64 - _lastRxMs >= guard - 50)
                {
                    _plusCount = 0;
                    _state = State.OnlineCommand;
                    Log.Info("Escape (+++) - modem in online command mode");
                    Respond("OK", 0);
                }
            });
        }
    }

    void CommandByte(byte b, long nowMs)
    {
        // PPP (0x7E) or SLIP (0xC0) framing in command mode means the dialer still thinks it's
        // online (we hung up, or VmModem restarted). The escaped frame bytes are mostly printable,
        // so echoing them would feed the PPP stack garbled copies of its own packets: swallow
        // everything until the line has been quiet for a moment.
        if (_discarding && nowMs - _lastCmdRxMs >= 500) _discarding = false;
        _lastCmdRxMs = nowMs;
        if (b == 0x7E || b == 0xC0)
        {
            if (!_discarding)
            {
                _line.Clear();
                if (nowMs - _lastFrameWarnMs >= 30_000)
                {
                    _lastFrameWarnMs = nowMs;
                    Log.Info($"VM is sending {(b == 0x7E ? "PPP" : "SLIP")} data but the modem isn't connected - ignoring it. " +
                             "The dialer still thinks it's online: hang up and dial again.");
                }
            }
            _discarding = true;
            return;
        }
        if (_discarding) return;

        if (b == _reg[3])
        {
            if (_echo) _echoBuf.Add(b);
            string line = _line.ToString();
            _line.Clear();
            ProcessLine(line);
            return;
        }
        if (b == _reg[4]) { if (_echo) _echoBuf.Add(b); return; }
        if (b == _reg[5] || b == 0x7F)
        {
            if (_line.Length > 0)
            {
                _line.Length--;
                if (_echo) _echoBuf.AddRange("\b \b"u8.ToArray());
            }
            return;
        }
        // Ignore non-printables (e.g. leftover PPP frames after a hang-up) and don't echo them,
        // so a PPP stack never sees its own frames looped back.
        if (b < 0x20 || b > 0x7E) return;

        if (_echo) _echoBuf.Add(b);
        if (_line.Length < 255) _line.Append((char)b);

        if (_line.Length == 2 && (_line[0] == 'A' || _line[0] == 'a') && _line[1] == '/')
        {
            _line.Clear();
            if (_echo) _echoBuf.Add(_reg[3]);
            ProcessLine(_lastCmd);
        }
    }

    void ProcessLine(string line)
    {
        line = line.Trim();
        int at = line.IndexOf("AT", StringComparison.OrdinalIgnoreCase);
        if (at < 0) return; // real modems silently ignore non-AT lines
        string cmd = line[(at + 2)..];
        _lastCmd = line[at..];
        Log.Info($"VM> AT{cmd}");
        var result = Execute(cmd, out var info);
        foreach (var s in info) SendInfo(s);
        if (result is { } r) Respond(r.Text, r.Code);
    }

    // ---- AT command interpreter -----------------------------------------------------------

    readonly record struct Result(string Text, int Code);
    static readonly Result Ok = new("OK", 0), Error = new("ERROR", 4), NoCarrier = new("NO CARRIER", 3);

    Result? Execute(string cmd, out List<string> info)
    {
        info = new List<string>();
        int i = 0;

        int Num(int dflt = 0)
        {
            int start = i;
            while (i < cmd.Length && char.IsDigit(cmd[i])) i++;
            return i > start && int.TryParse(cmd.AsSpan(start, i - start), out int v) ? v : dflt;
        }

        while (i < cmd.Length)
        {
            char c = char.ToUpperInvariant(cmd[i++]);
            switch (c)
            {
                case ' ': case ';': break;

                case 'D':
                    return Dial(cmd[i..]);

                case 'A':
                    Num();
                    return NoCarrier; // nobody is calling us

                case 'H':
                    Num();
                    Hangup("ATH");
                    break;

                case 'O':
                    Num();
                    if (_online == null) return NoCarrier;
                    if (info.Count > 0) { foreach (var s in info) SendInfo(s); info.Clear(); }
                    Respond(ConnectText, 1);
                    _state = State.Online;
                    _plusCount = 0;
                    Log.Info("Back online (ATO)");
                    return null;

                case 'Z':
                    Num();
                    Hangup("ATZ");
                    ResetSettings();
                    break;

                case 'E': _echo = Num() != 0; break;
                case 'V': _verbose = Num() != 0; break;
                case 'Q': _quiet = Num() == 1; break;
                case 'X': _x = Num(); break;

                case 'I':
                    info.Add(Num() switch
                    {
                        0 => "56000",
                        1 => "255",
                        3 => "VmModem V.90 56K Virtual Modem",
                        4 => "VmModem: virtual dial-up ISP (PPP/SLIP to host internet)",
                        _ => "VmModem",
                    });
                    break;

                case 'S':
                {
                    int n = Num();
                    if (n > 255) return Error;
                    _selectedReg = n;
                    if (i < cmd.Length && cmd[i] == '=') { i++; _reg[n] = (byte)Num(); }
                    else if (i < cmd.Length && cmd[i] == '?') { i++; info.Add(_reg[n].ToString("D3")); }
                    break;
                }
                case '=': _reg[_selectedReg] = (byte)Num(); break;
                case '?': info.Add(_reg[_selectedReg].ToString("D3")); break;

                case '&':
                {
                    if (i >= cmd.Length) return Error;
                    char sub = char.ToUpperInvariant(cmd[i++]);
                    Num();
                    if (sub == 'F') ResetSettings();
                    else if (sub == 'V')
                        info.Add($"E{(_echo ? 1 : 0)} Q{(_quiet ? 1 : 0)} V{(_verbose ? 1 : 0)} X{_x} " +
                                 $"S00:{_reg[0]:D3} S02:{_reg[2]:D3} S03:{_reg[3]:D3} S04:{_reg[4]:D3} " +
                                 $"S05:{_reg[5]:D3} S07:{_reg[7]:D3} S12:{_reg[12]:D3}");
                    break;
                }

                case '\\': case '%': case '*': case '#': case '-': case ')': case '"': case '$':
                    if (i < cmd.Length) i++;
                    Num();
                    break;

                case '+':
                    // Extended syntax (AT+MS=..., AT+FCLASS=0 ...): accept and skip to ';'.
                    while (i < cmd.Length && cmd[i] != ';') i++;
                    break;

                default:
                    if (char.IsLetter(c)) { Num(); break; } // B, C, L, M, N, P, T, W, Y ... accepted & ignored
                    return Error;
            }
        }
        return Ok;
    }

    Result? Dial(string dialString)
    {
        if (_online != null) return Error; // already connected (use ATH first)
        string number = dialString.Trim();
        if (number.EndsWith(';')) return Ok; // "voice" dial: return to command mode
        number = new string(number.Where(ch => char.IsDigit(ch) || ch is '*' or '#').ToArray());
        _dialed = number;

        Log.Info($"Dialing {(number.Length > 0 ? number : "(no number)")} ...");
        _state = State.Dialing;
        _dialTimer = _session.Loop.Schedule(TimeSpan.FromMilliseconds(Math.Max(0, _opt.DialDelayMs)), OnDialComplete);
        return null;
    }

    void OnDialComplete()
    {
        if (_state != State.Dialing) return;
        _dialTimer = null;
        _state = State.Online;
        _plusCount = 0;
        _lastRxMs = Environment.TickCount64;
        Respond(ConnectText, 1);
        Log.Info($"CONNECT ({ConnectText}) - carrier up");
        _online = new OnlineSession(_session, _opt, SendData, RemoteHangup);
        _online.Start();
    }

    string ConnectText => _x == 0 ? "CONNECT" : $"CONNECT {(_opt.Baud > 0 ? _opt.Baud : 115200)}";

    // ---- hang-up ------------------------------------------------------------------------------

    void Hangup(string why)
    {
        _dialTimer?.Dispose();
        _dialTimer = null;
        _escapeTimer?.Dispose();
        if (_online != null)
        {
            Log.Info($"Hang up ({why})");
            _online.Dispose();
            _online = null;
            _session.Out.Clear(); // drop anything still queued for the VM
        }
        _state = State.Command;
    }

    /// <summary>Called by the online session when the "remote end" hangs up (PPP terminate, logout).</summary>
    void RemoteHangup(string why)
    {
        if (_online == null) return;
        Log.Info($"Carrier lost ({why})");
        _online.Dispose();
        _online = null;
        _state = State.Command;
        Respond("NO CARRIER", 3);
    }

    // ---- output ------------------------------------------------------------------------------

    /// <summary>Data path for the online session; dropped while in online-command mode.</summary>
    long SendData(byte[] data)
    {
        if (_state != State.Online) return _session.Out.LastId;
        return _session.Out.Enqueue(data);
    }

    void FlushEcho()
    {
        if (_echoBuf.Count == 0) return;
        _session.Out.Enqueue(_echoBuf.ToArray());
        _echoBuf.Clear();
    }

    string Crlf => $"{(char)_reg[3]}{(char)_reg[4]}";

    void SendInfo(string text)
    {
        Log.Info($"modem> {text}");
        FlushEcho();
        _session.Out.Enqueue(Crlf + text + Crlf);
    }

    void Respond(string text, int code)
    {
        FlushEcho();
        if (_quiet) return;
        Log.Info($"modem> {text}{(_quiet ? " (suppressed: ATQ1)" : "")}");
        _session.Out.Enqueue(_verbose ? Crlf + text + Crlf : $"{code}{(char)_reg[3]}");
    }

    public void Tick() => _online?.Tick();

    public void Shutdown()
    {
        _dialTimer?.Dispose();
        _escapeTimer?.Dispose();
        _online?.Dispose();
        _online = null;
    }
}
