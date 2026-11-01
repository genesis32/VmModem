namespace VmModem.Link;

/// <summary>PPP in HDLC-like framing (RFC 1662): byte stuffing, ACCM and FCS-16.</summary>
public static class Hdlc
{
    public const byte Flag = 0x7E, Escape = 0x7D;
    public const ushort GoodFcs = 0xF0B8;

    static readonly ushort[] FcsTable = BuildTable();

    static ushort[] BuildTable()
    {
        var t = new ushort[256];
        for (int b = 0; b < 256; b++)
        {
            int v = b;
            for (int i = 0; i < 8; i++) v = (v & 1) != 0 ? (v >> 1) ^ 0x8408 : v >> 1;
            t[b] = (ushort)v;
        }
        return t;
    }

    public static ushort Fcs(ReadOnlySpan<byte> data, ushort fcs = 0xFFFF)
    {
        foreach (byte b in data) fcs = (ushort)((fcs >> 8) ^ FcsTable[(fcs ^ b) & 0xFF]);
        return fcs;
    }

    /// <summary>
    /// Frames <paramref name="frame"/> (address/control + protocol + information) for the wire:
    /// appends the FCS, escapes flag/escape bytes and every control character set in <paramref name="accm"/>.
    /// </summary>
    public static byte[] Encode(ReadOnlySpan<byte> frame, uint accm)
    {
        ushort fcs = (ushort)~Fcs(frame);
        var o = new List<byte>(frame.Length + frame.Length / 8 + 8) { Flag };
        void Put(byte b)
        {
            if (b == Flag || b == Escape || (b < 0x20 && (accm & (1u << b)) != 0))
            {
                o.Add(Escape);
                o.Add((byte)(b ^ 0x20));
            }
            else o.Add(b);
        }
        foreach (byte b in frame) Put(b);
        Put((byte)(fcs & 0xFF));
        Put((byte)(fcs >> 8));
        o.Add(Flag);
        return o.ToArray();
    }

    /// <summary>Incremental de-framer. Delivers frames whose FCS is good, with the FCS stripped.</summary>
    public sealed class Decoder
    {
        readonly List<byte> _buf = new(1600);
        readonly int _maxFrame;
        bool _escape;
        bool _overflow;

        public Decoder(int maxFrame = 4096) { _maxFrame = maxFrame; }

        public event Action<byte[]>? Frame;
        /// <summary>A frame whose FCS didn't match (corrupted or dropped bytes on the serial line).</summary>
        public event Action<byte[]>? BadFrame;
        public int BadFcsCount { get; private set; }
        public int GoodCount { get; private set; }

        public void Feed(ReadOnlySpan<byte> data)
        {
            foreach (byte raw in data)
            {
                if (raw == Flag)
                {
                    if (_buf.Count >= 4 && !_overflow && !_escape)
                    {
                        var f = _buf.ToArray();
                        if (Fcs(f) == GoodFcs) { GoodCount++; Frame?.Invoke(f[..^2]); }
                        else { BadFcsCount++; BadFrame?.Invoke(f); }
                    }
                    _buf.Clear();
                    _escape = false;
                    _overflow = false;
                    continue;
                }
                if (raw == Escape) { _escape = true; continue; }
                byte b = raw;
                if (_escape) { b ^= 0x20; _escape = false; }
                if (_buf.Count >= _maxFrame) { _overflow = true; continue; }
                _buf.Add(b);
            }
        }
    }
}
