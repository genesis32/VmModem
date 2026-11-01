using System.Net;
using System.Net.Sockets;

namespace VmModem.Net;

/// <summary>
/// NAT binding for one guest UDP source port: a host socket that sends to any
/// destination and relays any reply back (endpoint-independent mapping).
/// </summary>
public sealed class UdpBinding : IDisposable
{
    const long IdleTimeoutMs = 120_000;
    const int SIO_UDP_CONNRESET = -1744830452;

    readonly NatStack _nat;
    readonly Socket _sock;
    readonly Dictionary<IPEndPoint, (uint Ip, ushort Port)> _reverse = new();
    uint _guestIp;
    long _lastActive = Environment.TickCount64;
    bool _disposed;

    public ushort GuestPort { get; }

    public UdpBinding(NatStack nat, ushort guestPort)
    {
        _nat = nat;
        GuestPort = guestPort;
        _sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        // Stop ICMP port-unreachable from turning into exceptions on later receives.
        if (OperatingSystem.IsWindows())
            try { _sock.IOControl(SIO_UDP_CONNRESET, new byte[4], null); } catch (SocketException) { }
        _sock.Bind(new IPEndPoint(IPAddress.Any, 0));
        Log.Debug($"UDP flow from guest port {guestPort} via host port {((IPEndPoint)_sock.LocalEndPoint!).Port}");
        Receive();
    }

    public void Send(uint guestIp, uint dstIp, ushort dstPort, IPEndPoint real, byte[] payload)
    {
        _guestIp = guestIp;
        _lastActive = Environment.TickCount64;
        _reverse[real] = (dstIp, dstPort);
        try { _sock.SendTo(payload, real); }
        catch (SocketException ex) { Log.Debug($"UDP send to {real} failed: {ex.SocketErrorCode}"); }
    }

    void Receive()
    {
        if (_disposed) return;
        var buf = new byte[65536];
        _nat.Loop.Await(_sock.ReceiveFromAsync(buf, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0)), r =>
        {
            if (_disposed) return;
            _lastActive = Environment.TickCount64;
            var from = (IPEndPoint)r.RemoteEndPoint;
            var (ip, port) = _reverse.TryGetValue(from, out var v) ? v : (_nat.MapInbound(from.Address), (ushort)from.Port);
            if (ip != 0)
                _nat.SendPacket(Ip.BuildUdp(ip, _guestIp, port, GuestPort, buf.AsSpan(0, r.ReceivedBytes), _nat.NextIpId()));
            Receive();
        }, ex =>
        {
            if (_disposed) return;
            if (ex is SocketException) { Receive(); return; }
            Dispose();
        });
    }

    public void Tick(long now)
    {
        if (now - _lastActive > IdleTimeoutMs) Dispose();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _nat.RemoveUdp(this);
        _sock.Dispose();
    }
}
