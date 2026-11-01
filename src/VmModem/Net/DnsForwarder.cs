using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace VmModem.Net;

/// <summary>
/// The guest's DNS server (10.0.2.3). Queries are relayed verbatim to the host's
/// DNS servers; if none answer, A-record queries fall back to the Windows resolver
/// (which also covers hosts-file entries, VPN split DNS, DoH, etc).
/// </summary>
public sealed class DnsForwarder
{
    readonly EventLoop _loop;
    public IReadOnlyList<IPAddress> Servers { get; }

    public DnsForwarder(EventLoop loop, IReadOnlyList<IPAddress> configured)
    {
        _loop = loop;
        Servers = configured.Count > 0 ? configured.ToList() : DiscoverHostDnsServers();
        Log.Debug($"Upstream DNS: {(Servers.Count > 0 ? string.Join(", ", Servers) : "(none found - using system resolver)")}");
    }

    public static List<IPAddress> DiscoverHostDnsServers()
    {
        var list = new List<IPAddress>();
        try
        {
            var nics = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(n => n.GetIPProperties())
                .OrderByDescending(p => p.GatewayAddresses.Count > 0);
            foreach (var p in nics)
                foreach (var a in p.DnsAddresses)
                {
                    // fec0:0:0:ffff::1/2/3 are Windows' placeholder site-local DNS addresses.
                    if (a.AddressFamily == AddressFamily.InterNetworkV6 && a.IsIPv6SiteLocal) continue;
                    if (!list.Contains(a)) list.Add(a);
                }
        }
        catch (NetworkInformationException) { }
        return list.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToList();
    }

    public void Query(byte[] query, Action<byte[]> reply)
    {
        if (query.Length < 12) return;
        if (Log.IsEnabled(LogLevel.Debug) && TryParseQuestion(query, out var name, out var type, out _))
            Log.Debug($"DNS query {name} ({TypeName(type)})");
        _loop.Await(ResolveAsync(query), r => { if (r != null) reply(r); },
            ex => Log.Debug($"DNS failure: {ex.Message}"));
    }

    async Task<byte[]?> ResolveAsync(byte[] query)
    {
        foreach (var server in Servers.Take(3))
        {
            try
            {
                using var udp = new UdpClient(server.AddressFamily);
                udp.Connect(server, 53);
                await udp.SendAsync(query);
                using var cts = new CancellationTokenSource(2500);
                while (true)
                {
                    var r = await udp.ReceiveAsync(cts.Token);
                    if (r.Buffer.Length >= 12 && r.Buffer[0] == query[0] && r.Buffer[1] == query[1]) return r.Buffer;
                }
            }
            catch (OperationCanceledException) { Log.Debug($"DNS server {server} timed out"); }
            catch (SocketException ex) { Log.Debug($"DNS server {server}: {ex.SocketErrorCode}"); }
        }
        return await SystemResolveAsync(query);
    }

    /// <summary>Answers A queries via the OS resolver; anything else gets an empty answer.</summary>
    static async Task<byte[]?> SystemResolveAsync(byte[] query)
    {
        if (!TryParseQuestion(query, out var name, out var qtype, out int qend)) return null;
        ushort qclass = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(qend - 2));
        var addrs = new List<IPAddress>();
        bool nxdomain = false;
        if (qtype == 1 && qclass == 1)
        {
            try
            {
                addrs.AddRange(await Dns.GetHostAddressesAsync(name, AddressFamily.InterNetwork));
            }
            catch (SocketException) { nxdomain = true; }
        }

        var o = new List<byte>();
        o.AddRange(query.AsSpan(0, 2).ToArray());               // id
        byte rd = (byte)(query[2] & 0x01);
        o.Add((byte)(0x80 | rd));                                // QR, RD copied
        o.Add((byte)(0x80 | (nxdomain ? 3 : 0)));                // RA, rcode
        o.AddRange(new byte[] { 0, 1, 0, (byte)addrs.Count, 0, 0, 0, 0 });
        o.AddRange(query.AsSpan(12, qend - 12).ToArray());       // question
        foreach (var a in addrs.Take(16))
        {
            o.AddRange(new byte[] { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4 });
            o.AddRange(a.GetAddressBytes());
        }
        return o.ToArray();
    }

    public static bool TryParseQuestion(byte[] q, out string name, out ushort type, out int end)
    {
        name = ""; type = 0; end = 0;
        if (q.Length < 12 || BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(4)) < 1) return false;
        var sb = new StringBuilder();
        int i = 12;
        while (i < q.Length)
        {
            int len = q[i++];
            if (len == 0) break;
            if (len > 63 || i + len > q.Length) return false;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(q, i, len));
            i += len;
        }
        if (i + 4 > q.Length) return false;
        type = BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(i));
        end = i + 4;
        name = sb.ToString();
        return true;
    }

    static string TypeName(ushort t) => t switch
    {
        1 => "A", 2 => "NS", 5 => "CNAME", 12 => "PTR", 15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", _ => t.ToString(),
    };
}
