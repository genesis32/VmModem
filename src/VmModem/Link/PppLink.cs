using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using VmModem.Net;

namespace VmModem.Link;

/// <summary>
/// The "ISP side" of a PPP link (RFC 1661/1662/1332/1877): LCP, optional PAP/CHAP
/// (any credentials accepted), IPCP address + DNS assignment, IPv4 transport.
/// </summary>
public sealed class PppLink : ILink
{
    public const ushort ProtoIp = 0x0021, ProtoIpcp = 0x8021, ProtoLcp = 0xC021, ProtoPap = 0xC023, ProtoChap = 0xC223;

    const byte ConfReq = 1, ConfAck = 2, ConfNak = 3, ConfRej = 4, TermReq = 5, TermAck = 6,
        CodeRej = 7, ProtoRej = 8, EchoReq = 9, EchoRep = 10, DiscardReq = 11;

    const int RetryMs = 3000, MaxRetries = 10;

    readonly EventLoop _loop;
    readonly Options _opt;
    readonly Func<byte[], long> _send;
    readonly Action<byte[]> _deliver;
    readonly Action<uint> _guestIpAssigned;
    readonly Action<string> _hangup;
    readonly Hdlc.Decoder _decoder = new();

    // LCP
    byte _nextId = 1;
    byte _lcpReqId;
    uint _magic = (uint)RandomNumberGenerator.GetInt32(int.MaxValue) | 1;
    bool _reqAccm = true, _reqMagic = true;
    AuthMode _auth;
    bool _lcpOurAcked, _lcpPeerAcked, _lcpOpen;
    int _lcpRetries;
    long _lcpLastSend;
    uint _peerAccm = 0xFFFFFFFF;
    bool _peerPfc, _peerAcfc;
    int _peerMru = 1500;

    // Authentication
    bool _authDone;
    byte[] _chapChallenge = Array.Empty<byte>();
    byte _chapId;
    long _authLastSend;

    // IPCP
    bool _ipcpStarted, _ipcpOurAcked, _ipcpPeerAcked, _ipcpOpen;
    bool _reqOurIp = true;
    byte _ipcpReqId;
    int _ipcpRetries;
    long _ipcpLastSend;
    uint _assignedIp;

    bool _terminating;
    bool _disposed;
    long _rxFrames, _txFrames;
    long _phaseStart;
    bool _warnedStuck;

    public PppLink(EventLoop loop, Options opt, Func<byte[], long> send, Action<byte[]> deliver,
        Action<uint> guestIpAssigned, Action<string> hangup)
    {
        _loop = loop;
        _opt = opt;
        _send = send;
        _deliver = deliver;
        _guestIpAssigned = guestIpAssigned;
        _hangup = hangup;
        _auth = opt.Auth;
        _assignedIp = Ip.ToUInt(opt.GuestIp);
        _decoder.Frame += OnFrame;
        _decoder.BadFrame += OnBadFrame;
    }

    /// <summary>PPP was started by a frame from the VM, so our first request reaches a listening peer.</summary>
    public bool PeerAlreadyActive { get; init; }

    public string Name => "PPP";
    public int Mtu => Math.Clamp(_peerMru, 128, 1500);
    bool NetworkPhase => _lcpOpen && (_auth == AuthMode.None || _authDone);

    public void Start()
    {
        _phaseStart = Environment.TickCount64;
        Log.Info("PPP mode - negotiating");
        SendLcpConfReq();
    }

    public void OnData(byte[] data, int offset, int count) => _decoder.Feed(data.AsSpan(offset, count));

    // ---- framing --------------------------------------------------------------------------

    void OnBadFrame(byte[] f)
    {
        int bad = _decoder.BadFcsCount;
        string head = Convert.ToHexString(f.AsSpan(0, Math.Min(f.Length, 24)));
        if (bad <= 3 || bad % 50 == 0)
            Log.Warn($"PPP: discarded a {f.Length}-byte frame from the VM with a bad checksum ({bad} so far). " +
                     "Bytes are being lost or changed on the serial line (flow control / UART overrun?)");
        Log.Debug($"PPP: bad frame starts {head}");
    }

    void OnFrame(byte[] f)
    {
        // After a "ppp" command (or --session ppp) our first Configure-Request usually went out while
        // the dialer was still reading text. As soon as the VM speaks PPP, repeat it instead of waiting
        // for the retry timer. Not needed when the VM's own frame started PPP: a duplicate request can
        // make a peer that already opened LCP renegotiate.
        if (++_rxFrames == 1 && !PeerAlreadyActive && !_lcpOurAcked && !_terminating)
        {
            Log.Debug("PPP: first frame from VM - resending our LCP request");
            SendLcpConfReq();
        }
        int i = 0;
        if (f.Length >= 2 && f[0] == 0xFF && f[1] == 0x03) i = 2;
        if (i >= f.Length) return;
        ushort proto;
        if ((f[i] & 1) != 0) proto = f[i++]; // protocol field compressed
        else
        {
            if (i + 2 > f.Length) return;
            proto = BinaryPrimitives.ReadUInt16BigEndian(f.AsSpan(i));
            i += 2;
        }
        var payload = f.AsSpan(i);

        switch (proto)
        {
            case ProtoLcp: OnLcp(payload); break;
            case ProtoPap: OnPap(payload); break;
            case ProtoChap: OnChap(payload); break;
            case ProtoIpcp: OnIpcp(payload); break;
            case ProtoIp:
                if (_lcpOpen) _deliver(payload.ToArray());
                else Log.Debug("PPP: dropping IP packet received before LCP is up");
                break;
            default:
                Log.Debug(proto is 0x002D or 0x002F
                    ? $"PPP: rejecting Van Jacobson compressed packet (protocol 0x{proto:X4}) - turn VJ compression off in the guest"
                    : $"PPP: rejecting unsupported protocol 0x{proto:X4}");
                if (_lcpOpen)
                {
                    var rej = new byte[2 + Math.Min(payload.Length, Mtu - 6)];
                    BinaryPrimitives.WriteUInt16BigEndian(rej, proto);
                    payload[..(rej.Length - 2)].CopyTo(rej.AsSpan(2));
                    SendCp(ProtoLcp, ProtoRej, _nextId++, rej);
                }
                break;
        }
    }

    long SendPpp(ushort proto, ReadOnlySpan<byte> payload)
    {
        bool lcp = proto == ProtoLcp;
        var f = new byte[4 + payload.Length];
        int n = 0;
        if (lcp || !_lcpOpen || !_peerAcfc) { f[n++] = 0xFF; f[n++] = 0x03; }
        if (!lcp && _lcpOpen && _peerPfc && proto < 0x100) f[n++] = (byte)proto;
        else { f[n++] = (byte)(proto >> 8); f[n++] = (byte)proto; }
        payload.CopyTo(f.AsSpan(n));
        n += payload.Length;
        // Always escape XON/XOFF as well: a guest serial driver with software flow control
        // enabled would swallow them even though the client said it doesn't need them escaped.
        uint accm = lcp || !_lcpOpen ? 0xFFFFFFFF : _peerAccm | 0x000A0000;
        _txFrames++;
        return _send(Hdlc.Encode(f.AsSpan(0, n), accm));
    }

    long SendCp(ushort proto, byte code, byte id, ReadOnlySpan<byte> data)
    {
        var p = new byte[4 + data.Length];
        p[0] = code;
        p[1] = id;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
        data.CopyTo(p.AsSpan(4));
        Log.Write(IsKeepalive(code) ? LogLevel.Trace : LogLevel.Debug, $"PPP modem> {DescribeCp(proto, code, id, data)}");
        return SendPpp(proto, p);
    }

    public long SendIp(byte[] packet) => _lcpOpen && !_terminating ? SendPpp(ProtoIp, packet) : 0;

    // ---- LCP ------------------------------------------------------------------------------

    void SendLcpConfReq()
    {
        var o = new List<byte>();
        if (_reqAccm) o.AddRange(new byte[] { 2, 6, 0, 0, 0, 0 });
        if (_auth == AuthMode.Pap) o.AddRange(new byte[] { 3, 4, 0xC0, 0x23 });
        if (_auth == AuthMode.Chap) o.AddRange(new byte[] { 3, 5, 0xC2, 0x23, 0x05 });
        if (_reqMagic)
        {
            o.AddRange(new byte[] { 5, 6 });
            o.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(_magic)));
        }
        _lcpReqId = _nextId++;
        _lcpLastSend = Environment.TickCount64;
        SendCp(ProtoLcp, ConfReq, _lcpReqId, o.ToArray());
    }

    void OnLcp(ReadOnlySpan<byte> p)
    {
        if (!ParseCp(p, out byte code, out byte id, out var data)) return;
        Log.Write(IsKeepalive(code) ? LogLevel.Trace : LogLevel.Debug, $"PPP VM> {DescribeCp(ProtoLcp, code, id, data)}");
        switch (code)
        {
            case ConfReq:
            {
                if (_lcpOpen)
                {
                    Log.Info("PPP: peer renegotiating LCP");
                    LcpDown();
                    SendLcpConfReq();
                }
                var (reply, replyCode) = CheckLcpOptions(data);
                SendCp(ProtoLcp, replyCode, id, reply);
                if (replyCode == ConfAck)
                {
                    _lcpPeerAcked = true;
                    ApplyLcpOptions(data);
                    CheckLcpOpen();
                }
                break;
            }
            case ConfAck:
                if (id != _lcpReqId || _lcpOpen) break;
                _lcpOurAcked = true;
                CheckLcpOpen();
                break;
            case ConfNak:
                if (id != _lcpReqId) break;
                foreach (var (type, val) in ParseOptions(data))
                {
                    switch (type)
                    {
                        case 2: _reqAccm = false; break;
                        case 5: _magic = (uint)RandomNumberGenerator.GetInt32(int.MaxValue) | 1; break;
                        case 3:
                            if (val.Length >= 2 && val[0] == 0xC2 && val[1] == 0x23 && _auth != AuthMode.None) _auth = AuthMode.Chap;
                            else if (val.Length >= 2 && val[0] == 0xC0 && val[1] == 0x23 && _auth != AuthMode.None) _auth = AuthMode.Pap;
                            else { Log.Warn("PPP: client can't do our authentication; continuing without"); _auth = AuthMode.None; }
                            break;
                    }
                }
                SendLcpConfReq();
                break;
            case ConfRej:
                if (id != _lcpReqId) break;
                foreach (var (type, _) in ParseOptions(data))
                {
                    if (type == 2) _reqAccm = false;
                    if (type == 5) _reqMagic = false;
                    if (type == 3) { Log.Warn("PPP: client refused authentication; continuing without"); _auth = AuthMode.None; }
                }
                SendLcpConfReq();
                break;
            case TermReq:
                Log.Info("PPP: client sent Terminate-Request");
                SendCp(ProtoLcp, TermAck, id, ReadOnlySpan<byte>.Empty);
                Terminate("PPP terminated by client");
                break;
            case TermAck:
                break;
            case EchoReq:
                if (!_lcpOpen || data.Length < 4) break;
                var echo = data.ToArray();
                BinaryPrimitives.WriteUInt32BigEndian(echo, _magic);
                SendCp(ProtoLcp, EchoRep, id, echo);
                break;
            case EchoRep: case DiscardReq: case 12: case 13:
                break;
            case CodeRej:
                Log.Debug("PPP: peer sent Code-Reject");
                break;
            case ProtoRej:
                if (data.Length >= 2) Log.Debug($"PPP: peer rejected protocol 0x{BinaryPrimitives.ReadUInt16BigEndian(data):X4}");
                break;
            default:
                SendCp(ProtoLcp, CodeRej, _nextId++, p[..Math.Min(p.Length, Mtu - 8)]);
                break;
        }
    }

    (byte[] reply, byte code) CheckLcpOptions(ReadOnlySpan<byte> data)
    {
        var rej = new List<byte>();
        var nak = new List<byte>();
        foreach (var (type, val) in ParseOptions(data))
        {
            switch (type)
            {
                case 1: // MRU
                    if (val.Length != 2) goto default;
                    if (BinaryPrimitives.ReadUInt16BigEndian(val) < 128) nak.AddRange(new byte[] { 1, 4, 0x05, 0xDC });
                    break;
                case 2: // ACCM
                    if (val.Length != 4) goto default;
                    break;
                case 5: // Magic number
                    if (val.Length != 4) goto default;
                    break;
                case 7: case 8: // PFC / ACFC
                    if (val.Length != 0) goto default;
                    break;
                default: // auth-for-us, quality protocol, callback, multilink, ...
                    rej.Add(type);
                    rej.Add((byte)(val.Length + 2));
                    rej.AddRange(val.ToArray());
                    break;
            }
        }
        if (rej.Count > 0) return (rej.ToArray(), ConfRej);
        if (nak.Count > 0) return (nak.ToArray(), ConfNak);
        return (data.ToArray(), ConfAck);
    }

    void ApplyLcpOptions(ReadOnlySpan<byte> data)
    {
        _peerAccm = 0xFFFFFFFF; _peerPfc = false; _peerAcfc = false; _peerMru = 1500;
        foreach (var (type, val) in ParseOptions(data))
        {
            switch (type)
            {
                case 1: _peerMru = BinaryPrimitives.ReadUInt16BigEndian(val); break;
                case 2: _peerAccm = BinaryPrimitives.ReadUInt32BigEndian(val); break;
                case 7: _peerPfc = true; break;
                case 8: _peerAcfc = true; break;
            }
        }
    }

    void CheckLcpOpen()
    {
        if (_lcpOpen || !_lcpOurAcked || !_lcpPeerAcked) return;
        _lcpOpen = true;
        Log.Info($"PPP: LCP up (MRU {_peerMru}, ACCM {_peerAccm:X8}{(_peerPfc ? ", PFC" : "")}{(_peerAcfc ? ", ACFC" : "")}" +
                 $"{(_auth != AuthMode.None ? ", auth " + _auth.ToString().ToUpperInvariant() : "")})");
        if (_auth == AuthMode.Chap) SendChapChallenge();
        else if (_auth == AuthMode.None) StartIpcp();
        _authLastSend = Environment.TickCount64;
    }

    void LcpDown()
    {
        _lcpOpen = _lcpOurAcked = _lcpPeerAcked = false;
        _lcpRetries = 0;
        _authDone = false;
        _ipcpStarted = _ipcpOpen = _ipcpOurAcked = _ipcpPeerAcked = false;
        _peerAccm = 0xFFFFFFFF; _peerPfc = _peerAcfc = false;
    }

    // ---- PAP / CHAP ------------------------------------------------------------------------

    void OnPap(ReadOnlySpan<byte> p)
    {
        if (!ParseCp(p, out byte code, out byte id, out var data) || code != 1) return;
        string user = "";
        if (data.Length >= 1 && data.Length >= 1 + data[0]) user = Encoding.ASCII.GetString(data.Slice(1, data[0]));
        Log.Info($"PPP: PAP login '{user}' accepted");
        var msg = "Welcome"u8;
        var ack = new byte[1 + msg.Length];
        ack[0] = (byte)msg.Length;
        msg.CopyTo(ack.AsSpan(1));
        SendCp(ProtoPap, 2, id, ack);
        AuthSucceeded();
    }

    void SendChapChallenge()
    {
        _chapChallenge = RandomNumberGenerator.GetBytes(16);
        _chapId = _nextId++;
        var name = Encoding.ASCII.GetBytes(_opt.Hostname);
        var d = new byte[1 + _chapChallenge.Length + name.Length];
        d[0] = (byte)_chapChallenge.Length;
        _chapChallenge.CopyTo(d, 1);
        name.CopyTo(d, 1 + _chapChallenge.Length);
        _authLastSend = Environment.TickCount64;
        SendCp(ProtoChap, 1, _chapId, d);
    }

    void OnChap(ReadOnlySpan<byte> p)
    {
        if (!ParseCp(p, out byte code, out byte id, out var data) || code != 2) return;
        string user = data.Length >= 1 && data.Length > 1 + data[0] ? Encoding.ASCII.GetString(data[(1 + data[0])..]) : "";
        Log.Info($"PPP: CHAP login '{user}' accepted");
        SendCp(ProtoChap, 3, id, "Welcome"u8);
        AuthSucceeded();
    }

    void AuthSucceeded()
    {
        if (_authDone) return;
        _authDone = true;
        if (_lcpOpen) StartIpcp();
    }

    // ---- IPCP ------------------------------------------------------------------------------

    void StartIpcp()
    {
        if (_ipcpStarted) return;
        _ipcpStarted = true;
        _ipcpRetries = 0;
        SendIpcpConfReq();
    }

    void SendIpcpConfReq()
    {
        var o = new List<byte>();
        if (_reqOurIp)
        {
            o.AddRange(new byte[] { 3, 6 });
            o.AddRange(_opt.GatewayIp.GetAddressBytes());
        }
        _ipcpReqId = _nextId++;
        _ipcpLastSend = Environment.TickCount64;
        SendCp(ProtoIpcp, ConfReq, _ipcpReqId, o.ToArray());
    }

    void OnIpcp(ReadOnlySpan<byte> p)
    {
        if (!_lcpOpen) return;
        if (!ParseCp(p, out byte code, out byte id, out var data)) return;
        Log.Debug($"PPP VM> {DescribeCp(ProtoIpcp, code, id, data)}");
        if (!NetworkPhase)
        {
            // A client that skips the authentication we asked for: be lenient.
            if (code != ConfReq) return;
            Log.Warn("PPP: client skipped authentication; allowing");
            _authDone = true;
        }
        StartIpcp();

        switch (code)
        {
            case ConfReq:
            {
                if (_ipcpOpen) { _ipcpOpen = _ipcpOurAcked = _ipcpPeerAcked = false; SendIpcpConfReq(); }
                var (reply, replyCode, ip) = CheckIpcpOptions(data);
                SendCp(ProtoIpcp, replyCode, id, reply);
                if (replyCode == ConfAck)
                {
                    _ipcpPeerAcked = true;
                    if (ip != 0) _assignedIp = ip;
                    CheckIpcpOpen();
                }
                break;
            }
            case ConfAck:
                if (id != _ipcpReqId) break;
                _ipcpOurAcked = true;
                CheckIpcpOpen();
                break;
            case ConfNak: case ConfRej:
                if (id != _ipcpReqId) break;
                foreach (var (type, _) in ParseOptions(data))
                    if (type == 3) _reqOurIp = false;
                SendIpcpConfReq();
                break;
            case TermReq:
                SendCp(ProtoIpcp, TermAck, id, ReadOnlySpan<byte>.Empty);
                _ipcpOpen = _ipcpOurAcked = _ipcpPeerAcked = false;
                Log.Info("PPP: IPCP closed by client");
                break;
            case TermAck:
                break;
            default:
                SendCp(ProtoIpcp, CodeRej, _nextId++, p[..Math.Min(p.Length, Mtu - 8)]);
                break;
        }
    }

    (byte[] reply, byte code, uint ip) CheckIpcpOptions(ReadOnlySpan<byte> data)
    {
        var rej = new List<byte>();
        var nak = new List<byte>();
        uint ip = 0;
        uint gw = Ip.ToUInt(_opt.GatewayIp), dns = Ip.ToUInt(_opt.DnsIp);
        foreach (var (type, val) in ParseOptions(data))
        {
            switch (type)
            {
                case 3: // IP-Address
                {
                    if (val.Length != 4) goto default;
                    uint want = BinaryPrimitives.ReadUInt32BigEndian(val);
                    // 0.0.0.0 = "please assign me one". A fixed address configured in the guest is
                    // fine too (we NAT whatever the guest uses), unless it collides with our own.
                    if (want == 0 || want == gw || want == dns || (want >> 24) == 127 || want >= 0xE0000000)
                        AddAddrOpt(nak, 3, _assignedIp);
                    else ip = want;
                    break;
                }
                case 129: case 131: // Primary / secondary DNS (RFC 1877)
                    if (val.Length != 4) goto default;
                    if (BinaryPrimitives.ReadUInt32BigEndian(val) != dns) AddAddrOpt(nak, type, dns);
                    break;
                default: // VJ compression (2), IP-Addresses (1), NBNS (130/132), ...
                    rej.Add(type);
                    rej.Add((byte)(val.Length + 2));
                    rej.AddRange(val.ToArray());
                    break;
            }
        }
        if (rej.Count > 0) return (rej.ToArray(), ConfRej, 0);
        if (nak.Count > 0) return (nak.ToArray(), ConfNak, 0);
        return (data.ToArray(), ConfAck, ip);
    }

    static void AddAddrOpt(List<byte> list, byte type, uint addr)
    {
        list.Add(type);
        list.Add(6);
        list.Add((byte)(addr >> 24)); list.Add((byte)(addr >> 16)); list.Add((byte)(addr >> 8)); list.Add((byte)addr);
    }

    void CheckIpcpOpen()
    {
        if (_ipcpOpen || !_ipcpOurAcked || !_ipcpPeerAcked) return;
        _ipcpOpen = true;
        _warnedStuck = false;
        Log.Info($"PPP: IPCP up - guest {Ip.Str(_assignedIp)}, gateway {_opt.GatewayIp}, DNS {_opt.DnsIp}. Online!");
        _guestIpAssigned(_assignedIp);
    }

    // ---- timers / teardown --------------------------------------------------------------------

    public void Tick()
    {
        if (_terminating || _disposed) return;
        long now = Environment.TickCount64;
        if (!_ipcpOpen && !_warnedStuck && now - _phaseStart > 10_000)
        {
            _warnedStuck = true;
            string stage = !_lcpOpen
                ? $"LCP not up (we {(_lcpOurAcked ? "got" : "did not get")} an ACK for our options, VM's options {(_lcpPeerAcked ? "accepted" : "not yet accepted")})"
                : !NetworkPhase ? $"waiting for the VM to authenticate ({_auth})"
                : $"IPCP not up (our request {(_ipcpOurAcked ? "acked" : "not acked")}, VM's request {(_ipcpPeerAcked ? "accepted" : "not yet accepted")})";
            Log.Warn($"PPP: still not online after 10 s - {stage}. Frames from VM: {_rxFrames} good, {_decoder.BadFcsCount} bad checksum. " +
                     (_rxFrames == 0 ? "Nothing valid has arrived: is the VM's dialer in PPP mode (not SLIP)?" : "Run with -v to see the negotiation."));
        }
        if (!_lcpOurAcked && now - _lcpLastSend >= RetryMs)
        {
            if (++_lcpRetries > MaxRetries) { Terminate("LCP negotiation timed out"); return; }
            SendLcpConfReq();
        }
        if (_lcpOpen && !_authDone && _auth != AuthMode.None && now - _authLastSend >= RetryMs)
        {
            if (_auth == AuthMode.Chap) SendChapChallenge();
            else _authLastSend = now; // PAP: the client drives; just wait
        }
        if (_ipcpStarted && !_ipcpOurAcked && now - _ipcpLastSend >= RetryMs)
        {
            if (++_ipcpRetries > MaxRetries) { Terminate("IPCP negotiation timed out"); return; }
            SendIpcpConfReq();
        }
    }

    void Terminate(string why)
    {
        if (_terminating) return;
        _terminating = true;
        // Give the Terminate-Ack a moment to reach the guest, then drop "carrier".
        _loop.Schedule(TimeSpan.FromMilliseconds(500), () => _hangup(why));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _decoder.Frame -= OnFrame;
        _decoder.BadFrame -= OnBadFrame;
        Log.Info($"PPP stats: {_rxFrames} frames from VM ({_decoder.BadFcsCount} with bad checksum), {_txFrames} frames to VM");
    }

    // ---- helpers ----------------------------------------------------------------------------

    static bool ParseCp(ReadOnlySpan<byte> p, out byte code, out byte id, out ReadOnlySpan<byte> data)
    {
        code = id = 0;
        data = default;
        if (p.Length < 4) return false;
        int len = BinaryPrimitives.ReadUInt16BigEndian(p.Slice(2));
        if (len < 4 || len > p.Length) return false;
        code = p[0];
        id = p[1];
        data = p.Slice(4, len - 4);
        return true;
    }

    static List<(byte Type, byte[] Value)> ParseOptions(ReadOnlySpan<byte> data)
    {
        var list = new List<(byte, byte[])>();
        int i = 0;
        while (i + 2 <= data.Length)
        {
            byte t = data[i];
            int l = data[i + 1];
            if (l < 2 || i + l > data.Length) break;
            list.Add((t, data.Slice(i + 2, l - 2).ToArray()));
            i += l;
        }
        return list;
    }

    static bool IsKeepalive(byte code) => code is EchoReq or EchoRep or DiscardReq;

    static string DescribeCp(ushort proto, byte code, byte id, ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder($"{ProtoName(proto)} {CodeName(code)} id={id}");
        if (code is >= ConfReq and <= ConfRej && proto is ProtoLcp or ProtoIpcp)
        {
            sb.Append(" [");
            sb.AppendJoin(' ', ParseOptions(data).Select(o => DescribeOption(proto, o.Type, o.Value)));
            sb.Append(']');
        }
        return sb.ToString();
    }

    static string DescribeOption(ushort proto, byte t, byte[] v)
    {
        string Addr() => v.Length == 4 ? $"{v[0]}.{v[1]}.{v[2]}.{v[3]}" : Convert.ToHexString(v);
        string U32() => v.Length == 4 ? BinaryPrimitives.ReadUInt32BigEndian(v).ToString("X8") : Convert.ToHexString(v);
        if (proto == ProtoLcp)
            return t switch
            {
                1 when v.Length == 2 => $"MRU={BinaryPrimitives.ReadUInt16BigEndian(v)}",
                2 => $"ACCM={U32()}",
                3 when v.Length >= 2 && v[0] == 0xC0 && v[1] == 0x23 => "Auth=PAP",
                3 when v.Length >= 2 && v[0] == 0xC2 && v[1] == 0x23 => $"Auth=CHAP{(v.Length > 2 ? $"/{v[2]:X2}" : "")}",
                3 => $"Auth={Convert.ToHexString(v)}",
                4 => "Quality-Protocol",
                5 => $"Magic={U32()}",
                7 => "PFC",
                8 => "ACFC",
                13 => "Callback",
                17 => "Multilink-MRRU",
                19 => "Endpoint-Discriminator",
                _ => $"opt{t}={Convert.ToHexString(v)}",
            };
        return t switch
        {
            1 => "IP-Addresses(obsolete)",
            2 => $"VJ-Compression={Convert.ToHexString(v)}",
            3 => $"IP={Addr()}",
            129 => $"DNS1={Addr()}",
            130 => $"NBNS1={Addr()}",
            131 => $"DNS2={Addr()}",
            132 => $"NBNS2={Addr()}",
            _ => $"opt{t}={Convert.ToHexString(v)}",
        };
    }

    static string ProtoName(ushort p) => p switch
    {
        ProtoLcp => "LCP", ProtoIpcp => "IPCP", ProtoPap => "PAP", ProtoChap => "CHAP", _ => $"0x{p:X4}",
    };

    static string CodeName(byte c) => c switch
    {
        ConfReq => "Conf-Req", ConfAck => "Conf-Ack", ConfNak => "Conf-Nak", ConfRej => "Conf-Rej",
        TermReq => "Term-Req", TermAck => "Term-Ack", CodeRej => "Code-Rej", ProtoRej => "Proto-Rej",
        EchoReq => "Echo-Req", EchoRep => "Echo-Rep", _ => c.ToString(),
    };
}
