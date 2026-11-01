using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using VmModem.Link;

namespace VmModem.Net;

/// <summary>
/// User-mode NAT ("slirp"-style): terminates the guest's TCP connections and UDP flows
/// inside this process and re-originates them with ordinary host sockets, so no
/// drivers, adapters or admin rights are needed. Runs on the session event loop.
///
/// Virtual network: guest 10.0.2.15, gateway 10.0.2.2 (= host 127.0.0.1), DNS 10.0.2.3.
/// </summary>
public sealed class NatStack : IDisposable
{
    const int MaxTcp = 512, MaxUdp = 256, MaxPings = 16;

    public EventLoop Loop { get; }
    public Options Opt { get; }
    public SerialOut Serial { get; }

    public uint GuestIp { get; set; }
    public uint GatewayIp { get; }
    public uint DnsIp { get; }
    readonly uint _netmask;

    readonly Dictionary<(ushort, uint, ushort), TcpConn> _tcp = new();
    readonly Dictionary<ushort, UdpBinding> _udp = new();
    readonly DnsForwarder _dns;
    ILink? _link;
    ushort _ipId = (ushort)Random.Shared.Next();
    int _pings;
    bool _disposed;
    bool _warnedNonIpv4;

    // statistics
    public long PacketsIn, PacketsOut, BytesIn, BytesOut;
    public int TcpTotal, UdpTotal;

    public NatStack(EventLoop loop, Options opt, SerialOut serial)
    {
        Loop = loop;
        Opt = opt;
        Serial = serial;
        GuestIp = Ip.ToUInt(opt.GuestIp);
        GatewayIp = Ip.ToUInt(opt.GatewayIp);
        DnsIp = Ip.ToUInt(opt.DnsIp);
        _netmask = Ip.ToUInt(opt.Netmask);
        _dns = new DnsForwarder(loop, opt.DnsServers);
    }

    public void Attach(ILink link) => _link = link;

    public int Mtu => _link?.Mtu ?? 1500;

    /// <summary>MSS we can offer the guest / use towards it.</summary>
    public int Mss => Mtu - 40;

    /// <summary>How much may sit in the serial queue before TCP stops adding more.</summary>
    public long SerialBacklogLimit => Serial.BytesPerSecond > 0 ? Math.Max(2048, (long)Serial.BytesPerSecond) : 1 << 20;

    public ushort NextIpId() => _ipId++;

    /// <summary>Sends an IP packet to the guest (fragmenting if needed). Returns the serial frame id.</summary>
    public long SendPacket(byte[] packet)
    {
        if (_disposed || _link == null) return Serial.LastId;
        PacketsOut++;
        BytesOut += packet.Length;
        if (Log.IsEnabled(LogLevel.Trace)) Log.Trace("<- " + Describe(packet));
        if (packet.Length <= Mtu) return _link.SendIp(packet);
        if ((packet[6] & 0x40) != 0) { Log.Debug($"Dropping {packet.Length}-byte DF packet > MTU {Mtu}"); return Serial.LastId; }
        long id = 0;
        foreach (var f in Ip.Fragment(packet, Mtu)) id = _link.SendIp(f);
        return id;
    }

    // ---- inbound ------------------------------------------------------------------------

    public void OnIpPacket(byte[] p)
    {
        if (_disposed) return;
        if (p.Length < 20 || (p[0] >> 4) != 4)
        {
            if (!_warnedNonIpv4 && p.Length > 0)
            {
                _warnedNonIpv4 = true;
                Log.Warn((p[0] & 0x80) != 0 || (p[0] & 0xF0) == 0x70
                    ? "Guest is sending Van Jacobson compressed packets (CSLIP). Turn VJ compression off in the guest."
                    : $"Ignoring non-IPv4 packet (first byte 0x{p[0]:X2})");
            }
            return;
        }
        int ihl = (p[0] & 0x0F) * 4;
        int total = BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(2));
        if (ihl < 20 || total < ihl || total > p.Length) return;
        if (Ip.Checksum(p.AsSpan(0, ihl)) != 0) { Log.Warn("Dropping IP packet from VM with bad header checksum (corrupted on the serial line?)"); return; }
        if (total < p.Length) p = p[..total];

        PacketsIn++;
        BytesIn += p.Length;
        if (PacketsIn == 1) Log.Info($"First IP packet from VM: {Describe(p)}");
        if (Log.IsEnabled(LogLevel.Trace)) Log.Trace("-> " + Describe(p));

        ushort frag = BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(6));
        if ((frag & 0x3FFF) != 0) { Log.Debug("Dropping fragmented packet from guest (fragments unsupported)"); return; }

        uint src = BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(12));
        uint dst = BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(16));
        if (src != 0 && src != GuestIp && (src & 0xFF000000) != 0x7F000000)
        {
            Log.Info($"VM is sending from address {Ip.Str(src)} - replies will go there");
            GuestIp = src; // SLIP guests, or PPP guests with a static address
        }
        bool localBroadcast = (dst & _netmask) == (GatewayIp & _netmask) && (dst | _netmask) == 0xFFFFFFFF;
        if (dst >= 0xE0000000 || localBroadcast)
        {
            Log.Debug($"Ignoring broadcast/multicast packet to {Ip.Str(dst)}");
            return;
        }

        switch (p[9])
        {
            case Ip.ProtoTcp: HandleTcp(p, ihl, src, dst); break;
            case Ip.ProtoUdp: HandleUdp(p, ihl, src, dst); break;
            case Ip.ProtoIcmp: HandleIcmp(p, ihl, src, dst); break;
            default: Log.Debug($"Ignoring IP protocol {p[9]}"); break;
        }
    }

    /// <summary>Where a guest destination really goes on the host side, or null if unreachable.</summary>
    public IPEndPoint? MapOutbound(uint dst, ushort port)
    {
        if (dst == GatewayIp) return Opt.AllowHostLoopback ? new IPEndPoint(IPAddress.Loopback, port) : null;
        if (dst == DnsIp) return port == 53 && _dns.Servers.Count > 0 ? new IPEndPoint(_dns.Servers[0], 53) : null;
        if ((dst & _netmask) == (GatewayIp & _netmask)) return null; // nothing else lives on the virtual LAN
        if ((dst >> 24) is 0 or 127) return null;
        return new IPEndPoint(Ip.ToAddress(dst), port);
    }

    void HandleTcp(byte[] p, int ihl, uint src, uint dst)
    {
        var t = p.AsSpan(ihl);
        if (t.Length < 20) return;
        if (Ip.Fold(Ip.Sum(t, Ip.PseudoSum(src, dst, Ip.ProtoTcp, t.Length))) != 0)
        {
            Log.Debug("Bad TCP checksum from guest");
            return;
        }
        var seg = TcpSegment.Parse(p, ihl);
        if (seg == null) return;
        var s = seg.Value;
        var key = (s.SrcPort, dst, s.DstPort);

        if (_tcp.TryGetValue(key, out var conn)) { conn.OnSegment(s); return; }

        if ((s.Flags & (Ip.TcpSyn | Ip.TcpAck | Ip.TcpRst)) == Ip.TcpSyn)
        {
            var ep = MapOutbound(dst, s.DstPort);
            if (ep == null || _tcp.Count >= MaxTcp)
            {
                Log.Debug($"TCP {Ip.Str(dst)}:{s.DstPort} unreachable");
                SendRstFor(src, dst, s);
                return;
            }
            conn = new TcpConn(this, src, s.SrcPort, dst, s.DstPort);
            _tcp[key] = conn;
            TcpTotal++;
            conn.Open(ep, s);
            return;
        }
        if ((s.Flags & Ip.TcpRst) == 0) SendRstFor(src, dst, s);
    }

    internal void SendRstFor(uint guest, uint remote, in TcpSegment s)
    {
        byte[] pkt;
        if ((s.Flags & Ip.TcpAck) != 0)
            pkt = Ip.BuildTcp(remote, guest, s.DstPort, s.SrcPort, s.Ack, 0, Ip.TcpRst, 0, default, default, NextIpId());
        else
        {
            uint len = (uint)s.DataLength + ((s.Flags & Ip.TcpSyn) != 0 ? 1u : 0) + ((s.Flags & Ip.TcpFin) != 0 ? 1u : 0);
            pkt = Ip.BuildTcp(remote, guest, s.DstPort, s.SrcPort, 0, s.Seq + len, Ip.TcpRst | Ip.TcpAck, 0, default, default, NextIpId());
        }
        SendPacket(pkt);
    }

    internal void RemoveTcp(TcpConn c) => _tcp.Remove(c.Key);

    void HandleUdp(byte[] p, int ihl, uint src, uint dst)
    {
        var u = p.AsSpan(ihl);
        if (u.Length < 8) return;
        ushort sport = BinaryPrimitives.ReadUInt16BigEndian(u);
        ushort dport = BinaryPrimitives.ReadUInt16BigEndian(u[2..]);
        int len = BinaryPrimitives.ReadUInt16BigEndian(u[4..]);
        if (len < 8 || len > u.Length) return;
        if (BinaryPrimitives.ReadUInt16BigEndian(u[6..]) != 0 &&
            Ip.Fold(Ip.Sum(u[..len], Ip.PseudoSum(src, dst, Ip.ProtoUdp, len))) != 0)
        {
            Log.Debug("Bad UDP checksum from guest");
            return;
        }
        var payload = u.Slice(8, len - 8).ToArray();

        if (dst == DnsIp && dport == 53)
        {
            uint guest = src;
            _dns.Query(payload, reply =>
            {
                if (!_disposed) SendPacket(Ip.BuildUdp(DnsIp, guest, 53, sport, reply, NextIpId()));
            });
            return;
        }

        var ep = MapOutbound(dst, dport);
        if (ep == null)
        {
            Log.Debug($"UDP to {Ip.Str(dst)}:{dport} is not reachable - sending 'port unreachable'");
            SendUnreachable(p, ihl, src, dst, code: 3);
            return;
        }

        if (!_udp.TryGetValue(sport, out var b))
        {
            if (_udp.Count >= MaxUdp) return;
            b = new UdpBinding(this, sport);
            _udp[sport] = b;
            UdpTotal++;
        }
        b.Send(src, dst, dport, ep, payload);
    }

    internal void RemoveUdp(UdpBinding b) => _udp.Remove(b.GuestPort);

    void HandleIcmp(byte[] p, int ihl, uint src, uint dst)
    {
        var m = p.AsSpan(ihl);
        if (m.Length < 8) { Log.Debug("Dropping truncated ICMP packet"); return; }
        if (Ip.Checksum(m) != 0) { Log.Warn($"Dropping ICMP packet to {Ip.Str(dst)} with bad checksum (corrupted on the serial line?)"); return; }
        if (m[0] != 8) { Log.Debug($"Ignoring ICMP type {m[0]} to {Ip.Str(dst)} (only echo requests are relayed)"); return; }
        var rest = m[4..].ToArray(); // id, seq, data
        ushort seq = BinaryPrimitives.ReadUInt16BigEndian(m[6..]);
        string what = $"Ping {Ip.Str(dst)} (seq {seq}, {rest.Length - 4} bytes, TTL {p[8]})";

        if (dst == GatewayIp || dst == DnsIp)
        {
            Log.Info($"{what}: answered by VmModem itself");
            SendPacket(Ip.BuildIcmp(dst, src, 0, 0, rest, NextIpId()));
            return;
        }
        var ep = MapOutbound(dst, 0);
        if (ep == null)
        {
            Log.Info($"{what}: no such host on the virtual network - sending 'host unreachable'");
            SendUnreachable(p, ihl, src, dst, code: 1);
            return;
        }
        if (_pings >= MaxPings) { Log.Info($"{what}: dropped, {MaxPings} pings already outstanding"); return; }

        byte ttl = p[8];
        bool df = (p[6] & 0x40) != 0;
        var payload = rest[4..];
        var ping = new Ping();
        _pings++;
        var originalHeader = p.AsSpan(0, Math.Min(p.Length, ihl + 8)).ToArray();
        Log.Debug($"{what}: sending from host");
        Loop.Await(ping.SendPingAsync(ep.Address, 4000, payload, new PingOptions(Math.Max(1, (int)ttl), df)),
            reply =>
            {
                _pings--;
                ping.Dispose();
                if (_disposed) return;
                switch (reply.Status)
                {
                    case IPStatus.Success:
                        Log.Info($"{what}: reply in {reply.RoundtripTime} ms");
                        SendPacket(Ip.BuildIcmp(dst, src, 0, 0, rest, NextIpId()));
                        break;
                    case IPStatus.TtlExpired when reply.Address?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork:
                    {
                        // Lets tracert/traceroute in the guest see the real hops.
                        Log.Info($"{what}: TTL expired at {reply.Address}");
                        var body = new byte[4 + originalHeader.Length];
                        originalHeader.CopyTo(body, 4);
                        SendPacket(Ip.BuildIcmp(Ip.ToUInt(reply.Address), src, 11, 0, body, NextIpId()));
                        break;
                    }
                    case IPStatus.DestinationHostUnreachable or IPStatus.DestinationNetworkUnreachable:
                        Log.Info($"{what}: {reply.Status}");
                        SendUnreachable(p, ihl, src, dst, code: reply.Status == IPStatus.DestinationNetworkUnreachable ? (byte)0 : (byte)1);
                        break;
                    default:
                        Log.Info($"{what}: {reply.Status} (no reply from the host side either)");
                        break;
                }
            },
            ex => { _pings--; ping.Dispose(); Log.Info($"{what}: failed on the host: {ex.Message}"); });
    }

    internal void SendUnreachable(byte[] p, int ihl, uint guest, uint remote, byte code)
    {
        var body = new byte[4 + Math.Min(p.Length, ihl + 8)];
        p.AsSpan(0, body.Length - 4).CopyTo(body.AsSpan(4));
        SendPacket(Ip.BuildIcmp(remote == DnsIp || remote == GatewayIp ? remote : GatewayIp, guest, 3, code, body, NextIpId()));
    }

    /// <summary>Maps a host-side endpoint back to what the guest should see as the source.</summary>
    public uint MapInbound(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        if (IPAddress.IsLoopback(a)) return GatewayIp;
        return a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? Ip.ToUInt(a) : 0;
    }

    // ---- timers --------------------------------------------------------------------------

    public void Tick()
    {
        if (_disposed) return;
        long now = Environment.TickCount64;
        foreach (var c in _tcp.Values.ToArray()) c.Tick(now);
        foreach (var b in _udp.Values.ToArray()) b.Tick(now);
    }

    public void LogStats() =>
        Log.Info($"Session stats: {PacketsIn} packets / {BytesIn:N0} bytes from VM, {PacketsOut} packets / {BytesOut:N0} bytes to VM, " +
                 $"{TcpTotal} TCP connections, {UdpTotal} UDP flows");

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        foreach (var c in _tcp.Values.ToArray()) c.Abort(sendRst: false);
        foreach (var b in _udp.Values.ToArray()) b.Dispose();
        _tcp.Clear();
        _udp.Clear();
    }

    static string Describe(byte[] p)
    {
        if (p.Length < 20) return $"short packet ({p.Length})";
        int ihl = (p[0] & 0x0F) * 4;
        string src = Ip.Str(BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(12)));
        string dst = Ip.Str(BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(16)));
        if (p[9] == Ip.ProtoTcp && p.Length >= ihl + 20)
        {
            var t = p.AsSpan(ihl);
            byte f = t[13];
            string flags = string.Concat((f & Ip.TcpSyn) != 0 ? "S" : "", (f & Ip.TcpFin) != 0 ? "F" : "",
                (f & Ip.TcpRst) != 0 ? "R" : "", (f & Ip.TcpPsh) != 0 ? "P" : "", (f & Ip.TcpAck) != 0 ? "." : "");
            int dlen = p.Length - ihl - (t[12] >> 4) * 4;
            return $"TCP {src}:{BinaryPrimitives.ReadUInt16BigEndian(t)} > {dst}:{BinaryPrimitives.ReadUInt16BigEndian(t[2..])} [{flags}] " +
                   $"seq={BinaryPrimitives.ReadUInt32BigEndian(t[4..])} ack={BinaryPrimitives.ReadUInt32BigEndian(t[8..])} " +
                   $"win={BinaryPrimitives.ReadUInt16BigEndian(t[14..])} len={dlen}";
        }
        if (p[9] == Ip.ProtoUdp && p.Length >= ihl + 8)
        {
            var u = p.AsSpan(ihl);
            return $"UDP {src}:{BinaryPrimitives.ReadUInt16BigEndian(u)} > {dst}:{BinaryPrimitives.ReadUInt16BigEndian(u[2..])} len={p.Length - ihl - 8}";
        }
        if (p[9] == Ip.ProtoIcmp && p.Length >= ihl + 8)
        {
            var m = p.AsSpan(ihl);
            string kind = m[0] switch { 0 => "echo reply", 3 => "unreachable", 8 => "echo request", 11 => "time exceeded", _ => $"type {m[0]}" };
            return m[0] is 0 or 8
                ? $"ICMP {src} > {dst} {kind} id={BinaryPrimitives.ReadUInt16BigEndian(m[4..])} seq={BinaryPrimitives.ReadUInt16BigEndian(m[6..])} len={m.Length - 8}"
                : $"ICMP {src} > {dst} {kind} code={m[1]}";
        }
        return $"IP proto {p[9]} {src} > {dst} len={p.Length}";
    }
}
