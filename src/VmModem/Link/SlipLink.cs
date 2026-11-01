namespace VmModem.Link;

/// <summary>A link-layer protocol carrying IPv4 packets over the serial line.</summary>
public interface ILink : IDisposable
{
    string Name { get; }
    /// <summary>Largest IP packet the guest accepts.</summary>
    int Mtu { get; }
    void Start();
    void OnData(byte[] data, int offset, int count);
    /// <summary>Queues an IP packet for the guest; returns the serial queue id of the frame.</summary>
    long SendIp(byte[] packet);
    void Tick();
}

/// <summary>SLIP (RFC 1055). No negotiation: the guest must use the address we print.</summary>
public sealed class SlipLink : ILink
{
    public const byte End = 0xC0, Esc = 0xDB, EscEnd = 0xDC, EscEsc = 0xDD;
    public const int DefaultMtu = 1500;

    readonly Func<byte[], long> _send;
    readonly Action<byte[]> _deliver;
    readonly List<byte> _buf = new(1600);
    bool _esc;

    public SlipLink(Func<byte[], long> send, Action<byte[]> deliver)
    {
        _send = send;
        _deliver = deliver;
    }

    public string Name => "SLIP";
    public int Mtu => DefaultMtu;

    public void Start() => Log.Info("SLIP mode");

    public void OnData(byte[] data, int offset, int count)
    {
        for (int i = offset; i < offset + count; i++)
        {
            byte b = data[i];
            if (b == End)
            {
                if (_buf.Count > 0) _deliver(_buf.ToArray());
                _buf.Clear();
                _esc = false;
                continue;
            }
            if (b == Esc) { _esc = true; continue; }
            if (_esc)
            {
                b = b == EscEnd ? End : b == EscEsc ? Esc : b;
                _esc = false;
            }
            if (_buf.Count < 4096) _buf.Add(b);
        }
    }

    public static byte[] Encode(ReadOnlySpan<byte> packet)
    {
        var o = new List<byte>(packet.Length + 16) { End };
        foreach (byte b in packet)
        {
            if (b == End) { o.Add(Esc); o.Add(EscEnd); }
            else if (b == Esc) { o.Add(Esc); o.Add(EscEsc); }
            else o.Add(b);
        }
        o.Add(End);
        return o.ToArray();
    }

    public long SendIp(byte[] packet) => _send(Encode(packet));

    public void Tick() { }

    public void Dispose() { }
}
