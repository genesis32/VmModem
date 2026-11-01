// End-to-end test for VmModem. Plays the part of the VM: talks AT commands to the
// virtual modem, logs in, brings up PPP (or SLIP), then exercises DNS, ICMP, UDP and
// TCP through the NAT, optionally dropping a percentage of frames to test recovery.
//
//   VmModem.TestClient [--pipe name | --tcp port] [--slip] [--drop pct] [--size bytes] [--no-internet]

using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text;
using VmModem.Link;
using VmModem.Net;

string pipeName = "vmmodem";
int? tcpPort = null;
bool slip = false, internet = true, pipeServer = false, autodetect = false;
double drop = 0;
int size = 65536;
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--pipe": pipeName = args[++i]; break;
        case "--tcp": tcpPort = int.Parse(args[++i]); break;
        case "--slip": slip = true; break;
        case "--drop": drop = double.Parse(args[++i]) / 100; break;
        case "--size": size = int.Parse(args[++i]); break;
        case "--no-internet": internet = false; break;
        case "--pipe-server": pipeServer = true; break; // we create the pipe (tests VmModem --connect)
        case "--autodetect": autodetect = true; break;  // skip the "ppp" command; VmModem must detect PPP
    }
}

Stream stream;
if (pipeServer)
{
    var ps = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
    if (!ps.WaitForConnectionAsync().Wait(15000)) { Console.WriteLine("VmModem never connected"); return 1; }
    stream = ps;
}
else if (tcpPort is int p)
{
    var tc = new TcpClient();
    tc.Connect(IPAddress.Loopback, p);
    tc.NoDelay = true;
    stream = tc.GetStream();
}
else
{
    var pc = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
    pc.Connect(5000);
    stream = pc;
}

var g = new Guest(stream, drop);
int failures = 0;
void Check(bool ok, string what)
{
    Console.ForegroundColor = ok ? ConsoleColor.Green : ConsoleColor.Red;
    Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {what}");
    Console.ResetColor();
    if (!ok) failures++;
}

try
{
    // --- modem ---
    g.SendText("ATZ\r");
    Check(g.WaitText("OK", 3000), "ATZ -> OK");
    g.SendText("AT&FE1V1S0=0&C1&D2\\N3%C0+MS=V90\r");
    Check(g.WaitText("OK", 3000), "init string -> OK");
    g.SendText("ATI3\r");
    Check(g.WaitText("56K", 3000) && g.WaitText("OK", 3000), "ATI3 shows modem id");
    g.SendText("ATS12?\r");
    Check(g.WaitText("050", 3000), "ATS12? -> 050");
    g.SendText("ATDT5551234\r");
    Check(g.WaitText("CONNECT", 10000), "ATDT -> CONNECT");

    // --- terminal server login ---
    Check(g.WaitText("Username:", 5000), "Username prompt");
    g.SendText("tester\r");
    Check(g.WaitText("Password:", 5000), "Password prompt");
    g.SendText("secret\r");
    Check(g.WaitText(">", 5000), "command prompt");
    if (!autodetect)
    {
        g.SendText(slip ? "slip\r" : "ppp\r");
        Check(g.WaitText("MTU is", 5000), "address banner");
        g.WaitText("\n", 1000);
    }
    // with --autodetect we just start talking PPP at the prompt, like dialers that skip the command

    uint guestIp;
    if (slip)
    {
        g.StartSlip();
        guestIp = Ip.ToUInt(IPAddress.Parse("10.0.2.15"));
    }
    else
    {
        g.StartPpp();
        Check(g.NegotiatePpp(15000), $"PPP LCP + IPCP negotiated{(g.PapAccepted ? " (PAP login accepted)" : "")}");
        guestIp = g.GuestIp;
        Check(Ip.Str(guestIp) == "10.0.2.15", $"assigned IP {Ip.Str(guestIp)}");
        Check(Ip.Str(g.DnsFromIpcp) == "10.0.2.3", $"DNS via IPCP {Ip.Str(g.DnsFromIpcp)}");
    }
    g.LocalIp = guestIp;
    uint gw = Ip.ToUInt(IPAddress.Parse("10.0.2.2")), dnsIp = Ip.ToUInt(IPAddress.Parse("10.0.2.3"));

    // --- ICMP to gateway ---
    Check(g.Ping(gw, 3000), "ping 10.0.2.2");
    Check(g.PingUnreachable(Ip.ToUInt(IPAddress.Parse("10.0.2.99")), 3000), "ping 10.0.2.99 -> ICMP host unreachable");

    // --- local TCP through 10.0.2.2 -> 127.0.0.1 ---
    var payload = new byte[size];
    new Random(1234).NextBytes(payload);
    var server = new TcpListener(IPAddress.Loopback, 0);
    server.Start();
    int serverPort = ((IPEndPoint)server.LocalEndpoint).Port;
    var serverTask = Task.Run(async () =>
    {
        using var c = await server.AcceptTcpClientAsync();
        var s = c.GetStream();
        var req = new byte[256];
        int n = await s.ReadAsync(req);
        string r = Encoding.ASCII.GetString(req, 0, n);
        await s.WriteAsync(payload);
        c.Client.Shutdown(SocketShutdown.Send);
        // read until guest closes
        while (await s.ReadAsync(req) > 0) { }
        return r;
    });
    var tcp = new GuestTcp(g, guestIp, 40001, gw, (ushort)serverPort);
    Check(tcp.Connect(5000), $"TCP connect 10.0.2.2:{serverPort}");
    tcp.Send(Encoding.ASCII.GetBytes("HELLO SERVER\r\n"));
    var sw = Stopwatch.StartNew();
    var got = tcp.ReceiveUntilFin(Math.Max(60000, size / 2));
    sw.Stop();
    Check(got.AsSpan().SequenceEqual(payload),
        $"received {got.Length:N0}/{payload.Length:N0} bytes intact in {sw.Elapsed.TotalSeconds:F1}s " +
        $"({got.Length / Math.Max(0.001, sw.Elapsed.TotalSeconds):N0} B/s, {g.Dropped} frames dropped)");
    tcp.Close(3000);
    Check(serverTask.Wait(5000) && serverTask.Result.StartsWith("HELLO SERVER"), "server saw guest data and close");
    server.Stop();

    // --- refused port ---
    var refused = new GuestTcp(g, guestIp, 40002, gw, 1);
    Check(!refused.Connect(5000) && refused.WasReset, "TCP to closed port gets RST");

    if (internet)
    {
        // --- DNS via 10.0.2.3 ---
        var addrs = g.DnsQuery(dnsIp, 40010, "example.com", 8000);
        Check(addrs.Count > 0, $"DNS example.com -> {string.Join(", ", addrs.Select(Ip.Str))}");

        // --- DNS straight to 8.8.8.8 (generic UDP NAT path) ---
        var addrs2 = g.DnsQuery(Ip.ToUInt(IPAddress.Parse("8.8.8.8")), 40011, "example.org", 8000);
        Check(addrs2.Count > 0, $"UDP to 8.8.8.8:53 -> {string.Join(", ", addrs2.Select(Ip.Str))}");

        if (addrs.Count > 0)
        {
            Check(g.Ping(addrs[0], 6000), $"ping {Ip.Str(addrs[0])}");
            var web = new GuestTcp(g, guestIp, 40003, addrs[0], 80);
            Check(web.Connect(10000), "TCP connect example.com:80");
            web.Send(Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\nHost: example.com\r\nUser-Agent: VmModemTest\r\n\r\n"));
            var page = Encoding.ASCII.GetString(web.ReceiveUntilFin(30000));
            string first = page.Split('\n')[0].Trim();
            Check(first.StartsWith("HTTP/1."), $"HTTP response: '{first}', {page.Length:N0} bytes");
            web.Close(3000);
        }
    }

    // --- hang up ---
    if (slip)
    {
        Thread.Sleep(1200);
        g.SendRaw("+++"u8.ToArray());
        g.StartText();
        Check(g.WaitText("OK", 4000), "+++ escape -> OK");
        g.SendText("ATH\r");
        Check(g.WaitText("OK", 3000), "ATH -> OK");
    }
    else
    {
        g.StartText();
        g.SendLcpTerminate();
        Check(g.WaitText("NO CARRIER", 5000), "LCP Terminate -> NO CARRIER");
    }
    g.SendText("AT\r");
    Check(g.WaitText("OK", 3000), "back in command mode");

    // --- a dialer that still thinks it's online must not get its PPP frames echoed back ---
    Thread.Sleep(600);
    g.StartText();
    g.SendRaw(Hdlc.Encode(new byte[] { 0xFF, 0x03, 0xC0, 0x21, 1, 9, 0, 4 }, 0xFFFFFFFF));
    Thread.Sleep(700);
    Check(!g.PeekText().Contains('~'), "stray PPP frame in command mode is not echoed");
    g.SendText("AT\r");
    Check(g.WaitText("OK", 3000), "AT works again after stray frames");
}
catch (Exception ex)
{
    Check(false, "exception: " + ex);
}

Console.WriteLine(failures == 0 ? "ALL TESTS PASSED" : $"{failures} FAILURE(S)");
stream.Dispose();
return failures == 0 ? 0 : 1;

/// <summary>The simulated VM: a serial line with text, PPP or SLIP framing on top.</summary>
sealed class Guest
{
    enum Mode { Text, Ppp, Slip }

    readonly Stream _s;
    readonly double _drop;
    readonly Random _rnd = new(42);
    readonly object _lock = new();
    readonly StringBuilder _text = new();
    readonly BlockingCollection<(ushort Proto, byte[] Data)> _frames = new();
    readonly Hdlc.Decoder _hdlc = new();
    readonly List<byte> _slipBuf = new();
    readonly List<byte[]> _pendingIp = new();
    volatile Mode _mode = Mode.Text;
    byte _id = 1;
    readonly uint _magic = 0x12345678;
    ushort _ipId = 1;

    public uint GuestIp, DnsFromIpcp, LocalIp;
    public bool PapAccepted;
    public int Dropped;

    public Guest(Stream s, double drop)
    {
        _s = s;
        _drop = drop;
        _hdlc.Frame += f =>
        {
            int i = 0;
            if (f.Length >= 2 && f[0] == 0xFF && f[1] == 0x03) i = 2;
            ushort proto = (f[i] & 1) != 0 ? f[i++] : (ushort)(f[i++] << 8 | f[i++]);
            if (proto == PppLink.ProtoIp && _drop > 0 && _rnd.NextDouble() < _drop) { Dropped++; return; }
            _frames.Add((proto, f[i..]));
        };
        new Thread(ReadLoop) { IsBackground = true }.Start();
    }

    void ReadLoop()
    {
        var buf = new byte[4096];
        try
        {
            while (true)
            {
                int n = _s.Read(buf, 0, buf.Length);
                if (n == 0) break;
                lock (_lock)
                {
                    switch (_mode)
                    {
                        case Mode.Text: _text.Append(Encoding.Latin1.GetString(buf, 0, n)); Monitor.PulseAll(_lock); break;
                        case Mode.Ppp: _hdlc.Feed(buf.AsSpan(0, n)); break;
                        case Mode.Slip: FeedSlip(buf.AsSpan(0, n)); break;
                    }
                }
            }
        }
        catch (Exception) { }
    }

    bool _slipEsc;

    void FeedSlip(ReadOnlySpan<byte> d)
    {
        ref bool esc = ref _slipEsc; // escape state must survive across read chunks
        foreach (byte raw in d)
        {
            byte b = raw;
            if (b == SlipLink.End)
            {
                if (_slipBuf.Count > 0)
                {
                    if (_drop > 0 && _rnd.NextDouble() < _drop) Dropped++;
                    else _frames.Add((PppLink.ProtoIp, _slipBuf.ToArray()));
                }
                _slipBuf.Clear();
                continue;
            }
            if (b == SlipLink.Esc) { esc = true; continue; }
            if (esc) { b = b == SlipLink.EscEnd ? SlipLink.End : SlipLink.Esc; esc = false; }
            _slipBuf.Add(b);
        }
    }

    public void SendRaw(byte[] b) { lock (_s) { _s.Write(b); _s.Flush(); } }
    public void SendText(string t) => SendRaw(Encoding.ASCII.GetBytes(t));

    public bool WaitText(string needle, int timeoutMs)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        lock (_lock)
        {
            while (true)
            {
                string all = _text.ToString();
                int idx = all.IndexOf(needle, StringComparison.Ordinal);
                if (idx >= 0) { _text.Remove(0, idx + needle.Length); return true; }
                long left = deadline - Environment.TickCount64;
                if (left <= 0)
                {
                    Console.WriteLine($"   (timeout waiting for '{needle}', have: '{all.Replace("\r", "\\r").Replace("\n", "\\n")}')");
                    return false;
                }
                Monitor.Wait(_lock, (int)left);
            }
        }
    }

    public void StartText() { lock (_lock) { _mode = Mode.Text; _text.Clear(); } }
    public string PeekText() { lock (_lock) return _text.ToString(); }
    public void StartPpp() { lock (_lock) _mode = Mode.Ppp; }
    public void StartSlip() { lock (_lock) _mode = Mode.Slip; }

    // ---- PPP client ----

    void SendPpp(ushort proto, byte[] payload)
    {
        var f = new byte[4 + payload.Length];
        f[0] = 0xFF; f[1] = 0x03; f[2] = (byte)(proto >> 8); f[3] = (byte)proto;
        payload.CopyTo(f, 4);
        SendRaw(Hdlc.Encode(f, 0xFFFFFFFF));
    }

    void SendCp(ushort proto, byte code, byte id, byte[] data)
    {
        var p = new byte[4 + data.Length];
        p[0] = code; p[1] = id;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
        data.CopyTo(p, 4);
        SendPpp(proto, p);
    }

    public void SendLcpTerminate() => SendCp(PppLink.ProtoLcp, 5, _id++, Array.Empty<byte>());

    public bool NegotiatePpp(int timeoutMs)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        byte lcpId = _id++;
        var lcpOpts = new byte[] { 1, 4, 0x05, 0xDC, 2, 6, 0, 0, 0, 0, 5, 6, 0x12, 0x34, 0x56, 0x78, 7, 2, 8, 2 };
        SendCp(PppLink.ProtoLcp, 1, lcpId, lcpOpts);
        bool lcpUs = false, lcpThem = false, ipcpUs = false, ipcpThem = false, ipcpSent = false, wantsPap = false, papSent = false;
        byte ipcpId = 0;
        var ipcpOpts = new byte[] { 3, 6, 0, 0, 0, 0, 129, 6, 0, 0, 0, 0, 2, 6, 0x00, 0x2D, 0x0F, 0x01 /* VJ: expect reject */ };

        while (Environment.TickCount64 < deadline)
        {
            if (lcpUs && lcpThem && wantsPap && !papSent)
            {
                SendCp(PppLink.ProtoPap, 1, _id++, new byte[] { 6, (byte)'t', (byte)'e', (byte)'s', (byte)'t', (byte)'e', (byte)'r', 2, (byte)'p', (byte)'w' });
                papSent = true;
            }
            if (lcpUs && lcpThem && (!wantsPap || PapAccepted) && !ipcpSent)
            {
                ipcpId = _id++;
                SendCp(PppLink.ProtoIpcp, 1, ipcpId, ipcpOpts);
                ipcpSent = true;
            }
            if (ipcpUs && ipcpThem) return true;
            if (!_frames.TryTake(out var fr, 200)) continue;
            var (proto, d) = fr;
            if (d.Length < 4) continue;
            byte code = d[0], id = d[1];
            var data = d[4..BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(2))];
            if (proto == PppLink.ProtoLcp)
            {
                if (code == 1)
                {
                    SendCp(proto, 2, id, data);
                    lcpThem = true;
                    for (int i = 0; i + 4 <= data.Length; i += Math.Max((int)data[i + 1], 2))
                        if (data[i] == 3 && data[i + 2] == 0xC0 && data[i + 3] == 0x23) wantsPap = true;
                }
                else if (code == 2 && id == lcpId) lcpUs = true;
                else if (code is 3 or 4) Console.WriteLine($"   LCP nak/rej from server: {Convert.ToHexString(data)}");
            }
            else if (proto == PppLink.ProtoIpcp)
            {
                if (code == 1) { SendCp(proto, 2, id, data); ipcpThem = true; }
                else if (code == 2 && id == ipcpId)
                {
                    ipcpUs = true;
                    GuestIp = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(2));
                    DnsFromIpcp = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(8));
                }
                else if (code == 3 && id == ipcpId)
                {
                    // Take the server's suggestions.
                    for (int i = 0; i + 2 <= data.Length; i += data[i + 1])
                        for (int j = 0; j + 2 <= ipcpOpts.Length; j += ipcpOpts[j + 1])
                            if (ipcpOpts[j] == data[i]) Array.Copy(data, i, ipcpOpts, j, data[i + 1]);
                    ipcpId = _id++;
                    SendCp(proto, 1, ipcpId, ipcpOpts);
                }
                else if (code == 4 && id == ipcpId)
                {
                    // Drop rejected options.
                    var keep = new List<byte>();
                    for (int j = 0; j + 2 <= ipcpOpts.Length; j += ipcpOpts[j + 1])
                    {
                        bool rejected = false;
                        for (int i = 0; i + 2 <= data.Length; i += data[i + 1]) if (data[i] == ipcpOpts[j]) rejected = true;
                        if (!rejected) keep.AddRange(ipcpOpts.AsSpan(j, ipcpOpts[j + 1]).ToArray());
                    }
                    ipcpOpts = keep.ToArray();
                    ipcpId = _id++;
                    SendCp(proto, 1, ipcpId, ipcpOpts);
                }
            }
            else if (proto == PppLink.ProtoPap && code == 2) PapAccepted = true;
            else if (proto == PppLink.ProtoIp) _pendingIp.Add(data);
        }
        return false;
    }

    // ---- IP ----

    public void SendIp(byte[] packet)
    {
        if (_mode == Mode.Slip) SendRaw(SlipLink.Encode(packet));
        else SendPpp(PppLink.ProtoIp, packet);
    }

    public ushort NextId() => _ipId++;

    /// <summary>Waits for an IP packet matching <paramref name="match"/>, answering LCP echo etc meanwhile.</summary>
    public byte[]? WaitIp(Func<byte[], bool> match, int timeoutMs)
    {
        for (int i = 0; i < _pendingIp.Count; i++)
            if (match(_pendingIp[i])) { var p = _pendingIp[i]; _pendingIp.RemoveAt(i); return p; }
        var deadline = Environment.TickCount64 + timeoutMs;
        while (true)
        {
            long left = deadline - Environment.TickCount64;
            if (left <= 0) return null;
            if (!_frames.TryTake(out var fr, (int)Math.Min(left, 500))) continue;
            if (fr.Proto == PppLink.ProtoIp)
            {
                if (match(fr.Data)) return fr.Data;
                if (_pendingIp.Count < 100) _pendingIp.Add(fr.Data);
            }
            else if (fr.Proto == PppLink.ProtoLcp && fr.Data.Length >= 8 && fr.Data[0] == 9)
            {
                var rep = fr.Data[..BinaryPrimitives.ReadUInt16BigEndian(fr.Data.AsSpan(2))];
                rep[0] = 10;
                BinaryPrimitives.WriteUInt32BigEndian(rep.AsSpan(4), _magic);
                SendPpp(PppLink.ProtoLcp, rep);
            }
        }
    }

    public bool Ping(uint dst, int timeoutMs)
    {
        ushort ident = (ushort)Random.Shared.Next(1, 65535);
        var rest = new byte[4 + 32];
        BinaryPrimitives.WriteUInt16BigEndian(rest, ident);
        BinaryPrimitives.WriteUInt16BigEndian(rest.AsSpan(2), 1);
        for (int i = 4; i < rest.Length; i++) rest[i] = (byte)('a' + i % 26);
        SendIp(Ip.BuildIcmp(LocalIp, dst, 8, 0, rest, NextId()));
        var r = WaitIp(p => p[9] == Ip.ProtoIcmp && p[20] == 0 && BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(24)) == ident, timeoutMs);
        return r != null;
    }

    public bool PingUnreachable(uint dst, int timeoutMs)
    {
        var rest = new byte[4 + 8];
        BinaryPrimitives.WriteUInt16BigEndian(rest, 777);
        SendIp(Ip.BuildIcmp(LocalIp, dst, 8, 0, rest, NextId()));
        return WaitIp(p => p[9] == Ip.ProtoIcmp && p[20] == 3, timeoutMs) != null;
    }

    public List<uint> DnsQuery(uint server, ushort sport, string name, int timeoutMs)
    {
        var q = new List<byte> { 0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.')) { q.Add((byte)label.Length); q.AddRange(Encoding.ASCII.GetBytes(label)); }
        q.AddRange(new byte[] { 0, 0, 1, 0, 1 });
        byte[]? r = null;
        for (int attempt = 0; attempt < 3 && r == null; attempt++) // retry like a real resolver (frames may be dropped)
        {
            SendIp(Ip.BuildUdp(LocalIp, server, sport, 53, q.ToArray(), NextId()));
            r = WaitIp(p => p[9] == Ip.ProtoUdp && BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(22)) == sport, timeoutMs / 3);
        }
        var list = new List<uint>();
        if (r == null) return list;
        var m = r.AsSpan(28);
        int ancount = BinaryPrimitives.ReadUInt16BigEndian(m[6..]);
        int i = 12;
        while (m[i] != 0) i += m[i] + 1;
        i += 5;
        for (int a = 0; a < ancount && i < m.Length; a++)
        {
            if ((m[i] & 0xC0) == 0xC0) i += 2; else { while (m[i] != 0) i += m[i] + 1; i++; }
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(m[i..]);
            int rdlen = BinaryPrimitives.ReadUInt16BigEndian(m[(i + 8)..]);
            i += 10;
            if (type == 1 && rdlen == 4) list.Add(BinaryPrimitives.ReadUInt32BigEndian(m[i..]));
            i += rdlen;
        }
        return list;
    }
}

/// <summary>A deliberately simple guest-side TCP: in-order receive only, ACK everything.</summary>
sealed class GuestTcp
{
    readonly Guest _g;
    readonly uint _lip, _rip;
    readonly ushort _lport, _rport;
    uint _snd = 1000, _rcv;
    public bool WasReset;
    bool _finReceived;

    public GuestTcp(Guest g, uint lip, ushort lport, uint rip, ushort rport)
    {
        _g = g; _lip = lip; _lport = lport; _rip = rip; _rport = rport;
    }

    bool Mine(byte[] p) => p[9] == Ip.ProtoTcp &&
        BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(20)) == _rport &&
        BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(22)) == _lport;

    void Send(byte flags, ReadOnlySpan<byte> data, ReadOnlySpan<byte> opts = default) =>
        _g.SendIp(Ip.BuildTcp(_lip, _rip, _lport, _rport, _snd, _rcv, flags, 8192, opts, data, _g.NextId()));

    public bool Connect(int timeoutMs)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (true)
        {
            Send(Ip.TcpSyn, default, new byte[] { 2, 4, 0x05, 0xB4 }); // (re)transmit SYN, like a real stack
            var p = _g.WaitIp(Mine, (int)Math.Clamp(deadline - Environment.TickCount64, 1, 2500));
            if (p == null) { if (Environment.TickCount64 >= deadline) return false; continue; }
            var s = TcpSegment.Parse(p, 20)!.Value;
            if (s.Has(Ip.TcpRst)) { WasReset = true; return false; }
            if (s.Has(Ip.TcpSyn) && s.Has(Ip.TcpAck) && s.Ack == _snd + 1)
            {
                _snd++;
                _rcv = s.Seq + 1;
                Send(Ip.TcpAck, default);
                return true;
            }
        }
    }

    public void Send(byte[] data)
    {
        Send(Ip.TcpAck | Ip.TcpPsh, data);
        _snd += (uint)data.Length;
    }

    public byte[] ReceiveUntilFin(int timeoutMs)
    {
        var ms = new MemoryStream();
        var deadline = Environment.TickCount64 + timeoutMs;
        while (!_finReceived)
        {
            var p = _g.WaitIp(Mine, (int)Math.Max(1, deadline - Environment.TickCount64));
            if (p == null) break;
            var s = TcpSegment.Parse(p, 20)!.Value;
            if (s.Has(Ip.TcpRst)) { WasReset = true; break; }
            if (s.Seq == _rcv)
            {
                ms.Write(s.Data);
                _rcv += (uint)s.DataLength;
                if (s.Has(Ip.TcpFin)) { _rcv++; _finReceived = true; }
            }
            Send(Ip.TcpAck, default); // ACK (or dup-ACK if out of order)
        }
        return ms.ToArray();
    }

    public void Close(int timeoutMs)
    {
        Send(Ip.TcpFin | Ip.TcpAck, default);
        _snd++;
        var deadline = Environment.TickCount64 + timeoutMs;
        while (true)
        {
            var p = _g.WaitIp(Mine, (int)Math.Max(1, deadline - Environment.TickCount64));
            if (p == null) return;
            var s = TcpSegment.Parse(p, 20)!.Value;
            if (s.Has(Ip.TcpAck) && s.Ack == _snd) return;
        }
    }
}
