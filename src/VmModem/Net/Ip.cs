using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace VmModem.Net;

/// <summary>IPv4 / TCP / UDP / ICMP packet helpers. Addresses are host-order uints.</summary>
public static class Ip
{
    public const byte ProtoIcmp = 1, ProtoTcp = 6, ProtoUdp = 17;

    public const byte TcpFin = 0x01, TcpSyn = 0x02, TcpRst = 0x04, TcpPsh = 0x08, TcpAck = 0x10, TcpUrg = 0x20;

    public static uint ToUInt(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        if (a.AddressFamily != AddressFamily.InterNetwork) throw new ArgumentException("IPv4 only", nameof(a));
        Span<byte> b = stackalloc byte[4];
        a.TryWriteBytes(b, out _);
        return BinaryPrimitives.ReadUInt32BigEndian(b);
    }

    public static IPAddress ToAddress(uint a)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, a);
        return new IPAddress(b);
    }

    public static string Str(uint a) => $"{a >> 24}.{(a >> 16) & 255}.{(a >> 8) & 255}.{a & 255}";

    /// <summary>Ones-complement sum (not yet folded/complemented).</summary>
    public static uint Sum(ReadOnlySpan<byte> data, uint sum = 0)
    {
        int i = 0;
        for (; i + 1 < data.Length; i += 2) sum += (uint)(data[i] << 8 | data[i + 1]);
        if (i < data.Length) sum += (uint)(data[i] << 8);
        return sum;
    }

    public static ushort Fold(uint sum)
    {
        while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    public static ushort Checksum(ReadOnlySpan<byte> data) => Fold(Sum(data));

    public static uint PseudoSum(uint src, uint dst, byte proto, int length) =>
        (src >> 16) + (src & 0xFFFF) + (dst >> 16) + (dst & 0xFFFF) + proto + (uint)length;

    /// <summary>Builds an IPv4 packet around an already-checksummed L4 payload.</summary>
    public static byte[] BuildIp(uint src, uint dst, byte proto, ReadOnlySpan<byte> l4, ushort id, bool dontFragment, byte ttl = 64)
    {
        var p = new byte[20 + l4.Length];
        p[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), id);
        if (dontFragment) p[6] = 0x40;
        p[8] = ttl;
        p[9] = proto;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(12), src);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(16), dst);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), Checksum(p.AsSpan(0, 20)));
        l4.CopyTo(p.AsSpan(20));
        return p;
    }

    public static byte[] BuildTcp(uint src, uint dst, ushort sport, ushort dport, uint seq, uint ack,
        byte flags, ushort window, ReadOnlySpan<byte> options, ReadOnlySpan<byte> data, ushort ipId)
    {
        int optLen = (options.Length + 3) & ~3;
        int hlen = 20 + optLen;
        var t = new byte[hlen + data.Length];
        BinaryPrimitives.WriteUInt16BigEndian(t.AsSpan(0), sport);
        BinaryPrimitives.WriteUInt16BigEndian(t.AsSpan(2), dport);
        BinaryPrimitives.WriteUInt32BigEndian(t.AsSpan(4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(t.AsSpan(8), ack);
        t[12] = (byte)((hlen / 4) << 4);
        t[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(t.AsSpan(14), window);
        options.CopyTo(t.AsSpan(20));
        data.CopyTo(t.AsSpan(hlen));
        ushort cs = Fold(Sum(t, PseudoSum(src, dst, ProtoTcp, t.Length)));
        BinaryPrimitives.WriteUInt16BigEndian(t.AsSpan(16), cs);
        return BuildIp(src, dst, ProtoTcp, t, ipId, dontFragment: true);
    }

    public static byte[] BuildUdp(uint src, uint dst, ushort sport, ushort dport, ReadOnlySpan<byte> data, ushort ipId)
    {
        var u = new byte[8 + data.Length];
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(0), sport);
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(2), dport);
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(4), (ushort)u.Length);
        data.CopyTo(u.AsSpan(8));
        ushort cs = Fold(Sum(u, PseudoSum(src, dst, ProtoUdp, u.Length)));
        if (cs == 0) cs = 0xFFFF;
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(6), cs);
        return BuildIp(src, dst, ProtoUdp, u, ipId, dontFragment: false);
    }

    public static byte[] BuildIcmp(uint src, uint dst, byte type, byte code, ReadOnlySpan<byte> rest, ushort ipId, byte ttl = 64)
    {
        // rest = everything after the checksum (id/seq/data, or unused + original datagram)
        var m = new byte[4 + rest.Length];
        m[0] = type;
        m[1] = code;
        rest.CopyTo(m.AsSpan(4));
        BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(2), Checksum(m));
        return BuildIp(src, dst, ProtoIcmp, m, ipId, dontFragment: false, ttl);
    }

    /// <summary>Splits an IPv4 packet into fragments that fit <paramref name="mtu"/>.</summary>
    public static List<byte[]> Fragment(byte[] packet, int mtu)
    {
        int ihl = (packet[0] & 0x0F) * 4;
        int payload = packet.Length - ihl;
        int maxData = (mtu - ihl) / 8 * 8;
        var list = new List<byte[]>();
        for (int off = 0; off < payload; off += maxData)
        {
            int n = Math.Min(maxData, payload - off);
            var f = new byte[ihl + n];
            packet.AsSpan(0, ihl).CopyTo(f);
            packet.AsSpan(ihl + off, n).CopyTo(f.AsSpan(ihl));
            BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(2), (ushort)f.Length);
            bool more = off + n < payload;
            BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(6), (ushort)((more ? 0x2000 : 0) | (off / 8)));
            f[10] = f[11] = 0;
            BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(10), Checksum(f.AsSpan(0, ihl)));
            list.Add(f);
        }
        return list;
    }

    public static bool SeqLt(uint a, uint b) => (int)(a - b) < 0;
    public static bool SeqLe(uint a, uint b) => (int)(a - b) <= 0;
    public static bool SeqGt(uint a, uint b) => (int)(a - b) > 0;
    public static bool SeqGe(uint a, uint b) => (int)(a - b) >= 0;
}
