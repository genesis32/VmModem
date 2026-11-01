using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace VmModem.Net;

public readonly struct TcpSegment
{
    public ushort SrcPort { get; init; }
    public ushort DstPort { get; init; }
    public uint Seq { get; init; }
    public uint Ack { get; init; }
    public byte Flags { get; init; }
    public ushort Window { get; init; }
    public int Mss { get; init; }
    public ArraySegment<byte> Data { get; init; }
    public int DataLength => Data.Count;
    public bool Has(byte flag) => (Flags & flag) != 0;

    public static TcpSegment? Parse(byte[] p, int ihl)
    {
        var t = p.AsSpan(ihl);
        int hlen = (t[12] >> 4) * 4;
        if (hlen < 20 || hlen > t.Length) return null;
        int mss = -1;
        for (int i = 20; i < hlen;)
        {
            byte kind = t[i];
            if (kind == 0) break;
            if (kind == 1) { i++; continue; }
            if (i + 1 >= hlen) break;
            int len = t[i + 1];
            if (len < 2 || i + len > hlen) break;
            if (kind == 2 && len == 4) mss = BinaryPrimitives.ReadUInt16BigEndian(t[(i + 2)..]);
            i += len;
        }
        return new TcpSegment
        {
            SrcPort = BinaryPrimitives.ReadUInt16BigEndian(t),
            DstPort = BinaryPrimitives.ReadUInt16BigEndian(t[2..]),
            Seq = BinaryPrimitives.ReadUInt32BigEndian(t[4..]),
            Ack = BinaryPrimitives.ReadUInt32BigEndian(t[8..]),
            Flags = t[13],
            Window = BinaryPrimitives.ReadUInt16BigEndian(t[14..]),
            Mss = mss,
            Data = new ArraySegment<byte>(p, ihl + hlen, t.Length - hlen),
        };
    }
}

/// <summary>
/// One guest TCP connection, terminated here and relayed to a host socket.
/// We play the server side of the handshake: the SYN-ACK is only sent once the
/// real host connection succeeds (otherwise the guest gets a RST).
/// </summary>
public sealed class TcpConn
{
    enum State { Connecting, SynReceived, Established, Closed }

    const int RcvWindowMax = 16384;   // what we advertise to the guest
    const int SendBufMax = 65536;     // host data buffered for the guest
    const int InitialRtoMs = 1500, MaxRtoMs = 30000, MaxRetransmits = 12;
    const long IdleTimeoutMs = 2 * 60 * 60 * 1000, HalfClosedTimeoutMs = 5 * 60 * 1000;

    readonly NatStack _nat;
    readonly uint _guestIp, _remoteIp;
    readonly ushort _guestPort, _remotePort;
    public (ushort, uint, ushort) Key => (_guestPort, _remoteIp, _remotePort);

    Socket? _sock;
    IPEndPoint? _endpoint;
    State _state = State.Connecting;

    // Sequence space towards the guest
    uint _iss, _sndUna, _sndNxt, _sndMax;
    int _sndWnd;            // guest's advertised window
    int _cwnd;              // simple congestion window (slow start after loss)
    int _mss = 536;
    readonly ByteBuffer _sendBuf = new(); // data starting at _sndUna
    bool _hostEof, _finSent, _finAcked, _finSeqValid;
    uint _finSeq;

    // Sequence space from the guest
    uint _rcvNxt;
    bool _guestFin;
    Queue<byte[]> _hostWriteQ = new();
    int _hostWritePending;
    bool _writing, _shutdownSent;
    int _lastAdvWnd;
    bool _ackNeeded;

    bool _receiving, _readPaused;

    // Retransmission
    int _rtoMs = InitialRtoMs;
    long _rtoStart = -1;
    long _lastSegFrameId;
    int _retransmits;
    int _dupAcks;
    long _synSentAt;
    long _lastActivity = Environment.TickCount64;
    long _bytesToGuest, _bytesFromGuest;

    public TcpConn(NatStack nat, uint guestIp, ushort guestPort, uint remoteIp, ushort remotePort)
    {
        _nat = nat;
        _guestIp = guestIp;
        _guestPort = guestPort;
        _remoteIp = remoteIp;
        _remotePort = remotePort;
    }

    string Name => $"{Ip.Str(_remoteIp)}:{_remotePort}" +
                   (_endpoint != null && !_endpoint.Address.Equals(Ip.ToAddress(_remoteIp)) ? $" (via {_endpoint})" : "");

    int Window => Math.Clamp(RcvWindowMax - _hostWritePending, 0, 65535);
    int EffMss => Math.Max(64, Math.Min(_mss, _nat.Mss));

    // ---- setup ----------------------------------------------------------------------------

    public void Open(IPEndPoint ep, in TcpSegment syn)
    {
        _endpoint = ep;
        _rcvNxt = syn.Seq + 1;
        _sndWnd = syn.Window;
        if (syn.Mss > 0) _mss = syn.Mss;
        _iss = (uint)Random.Shared.NextInt64();
        _sndUna = _sndNxt = _sndMax = _iss;
        _cwnd = 4 * EffMss;

        Log.Debug($"TCP {Ip.Str(_guestIp)}:{_guestPort} -> {Name} connecting");
        _sock = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        _nat.Loop.Await(_sock.ConnectAsync(ep, cts.Token).AsTask(),
            () => { cts.Dispose(); OnConnected(); },
            ex => { cts.Dispose(); OnConnectFailed(ex); });
    }

    void OnConnected()
    {
        if (_state == State.Closed) return;
        Log.Info($"TCP connected to {Name}");
        _state = State.SynReceived;
        SendSynAck();
        StartReceive();
    }

    void OnConnectFailed(Exception ex)
    {
        if (_state == State.Closed) return;
        Log.Info($"TCP connect to {Name} failed: {Describe(ex)}");
        // RST|ACK refuses the guest's SYN.
        _nat.SendPacket(Ip.BuildTcp(_remoteIp, _guestIp, _remotePort, _guestPort, 0, _rcvNxt,
            Ip.TcpRst | Ip.TcpAck, 0, default, default, _nat.NextIpId()));
        Close(abortive: true);
    }

    void SendSynAck()
    {
        Span<byte> opt = stackalloc byte[4];
        opt[0] = 2; opt[1] = 4;
        BinaryPrimitives.WriteUInt16BigEndian(opt[2..], (ushort)_nat.Mss);
        SendSegment(Ip.TcpSyn, _iss, default, opt);
        _sndNxt = _sndMax = _iss + 1;
        _synSentAt = Environment.TickCount64;
    }

    // ---- guest -> host --------------------------------------------------------------------

    public void OnSegment(in TcpSegment s)
    {
        _lastActivity = Environment.TickCount64;

        if (s.Has(Ip.TcpRst))
        {
            Log.Debug($"TCP {Name}: reset by guest");
            Close(abortive: true);
            return;
        }

        switch (_state)
        {
            case State.Connecting:
                return; // retransmitted SYN while the host connect is in progress
            case State.SynReceived:
                if (s.Has(Ip.TcpSyn)) { if (!s.Has(Ip.TcpAck)) SendSynAck(); return; }
                if (!s.Has(Ip.TcpAck)) return;
                if (s.Ack != _iss + 1)
                {
                    _nat.SendRstFor(_guestIp, _remoteIp, s);
                    return;
                }
                _state = State.Established;
                _sndUna = _iss + 1;
                _rtoStart = -1;
                _rtoMs = InitialRtoMs;
                _retransmits = 0;
                break;
            case State.Established:
                if (s.Has(Ip.TcpSyn)) { _ackNeeded = true; FlushAck(); return; }
                break;
            default:
                return;
        }

        if (s.Has(Ip.TcpAck)) ProcessAck(s);
        ProcessData(s);
        TrySend();
        FlushAck();
        CheckDone();
    }

    void ProcessAck(in TcpSegment s)
    {
        uint a = s.Ack;
        if (Ip.SeqGt(a, _sndMax)) { _ackNeeded = true; return; }

        if (Ip.SeqGt(a, _sndUna))
        {
            uint acked = a - _sndUna;
            int data = (int)Math.Min(acked, (uint)_sendBuf.Count);
            _sendBuf.Discard(data);
            if (_finSeqValid && Ip.SeqGe(a, _finSeq + 1)) _finAcked = true;
            _sndUna = a;
            if (Ip.SeqLt(_sndNxt, _sndUna)) _sndNxt = _sndUna;
            _dupAcks = 0;
            _retransmits = 0;
            _rtoMs = InitialRtoMs;
            _rtoStart = -1;
            _cwnd = Math.Min(_cwnd + EffMss, 65535);
            if (_readPaused && _sendBuf.Count < SendBufMax / 2) { _readPaused = false; StartReceive(); }
        }
        else if (a == _sndUna && s.DataLength == 0 && !s.Has(Ip.TcpFin) && s.Window == _sndWnd && _sndNxt != _sndUna)
        {
            if (++_dupAcks == 3) FastRetransmit();
        }
        _sndWnd = s.Window;
    }

    void ProcessData(in TcpSegment s)
    {
        int len = s.DataLength;
        bool fin = s.Has(Ip.TcpFin);
        if (len == 0 && !fin) return;

        int off = 0;
        if (s.Seq != _rcvNxt)
        {
            if (!Ip.SeqLt(s.Seq, _rcvNxt)) { _ackNeeded = true; return; } // out of order: drop, dup-ACK
            uint dup = _rcvNxt - s.Seq;
            if (dup > (uint)len || (dup == (uint)len && (!fin || _guestFin))) { _ackNeeded = true; return; } // old retransmit
            off = (int)dup;
            len -= off;
        }

        if (len > 0 && !_guestFin)
        {
            var chunk = new byte[len];
            Array.Copy(s.Data.Array!, s.Data.Offset + off, chunk, 0, len);
            _hostWriteQ.Enqueue(chunk);
            _hostWritePending += len;
            _bytesFromGuest += len;
            _rcvNxt += (uint)len;
        }
        if (fin && !_guestFin)
        {
            _guestFin = true;
            _rcvNxt++;
            Log.Debug($"TCP {Name}: guest closed its side");
        }
        _ackNeeded = true;
        PumpHostWrite();
    }

    void PumpHostWrite()
    {
        if (_writing || _sock == null || _state == State.Closed) return;
        if (_hostWriteQ.Count == 0)
        {
            if (_guestFin && !_shutdownSent)
            {
                _shutdownSent = true;
                try { _sock.Shutdown(SocketShutdown.Send); } catch (SocketException) { } catch (ObjectDisposedException) { }
            }
            return;
        }
        var buf = _hostWriteQ.Peek();
        _writing = true;
        _nat.Loop.Await(_sock.SendAsync(buf.AsMemory(), SocketFlags.None).AsTask(), n =>
        {
            _writing = false;
            if (_state == State.Closed) return;
            _hostWriteQ.Dequeue();
            if (n < buf.Length) _hostWriteQ = RequeueFront(buf[n..]);
            _hostWritePending -= n;
            // Re-open our receive window if it had closed down.
            if (_lastAdvWnd < RcvWindowMax / 2 && Window >= RcvWindowMax / 2) { _ackNeeded = true; FlushAck(); }
            PumpHostWrite();
            CheckDone();
        }, HostError);
    }

    Queue<byte[]> RequeueFront(byte[] rest)
    {
        var q = new Queue<byte[]>();
        q.Enqueue(rest);
        foreach (var b in _hostWriteQ) q.Enqueue(b);
        return q;
    }

    // ---- host -> guest --------------------------------------------------------------------

    void StartReceive()
    {
        if (_receiving || _hostEof || _sock == null || _state == State.Closed) return;
        if (_sendBuf.Count >= SendBufMax) { _readPaused = true; return; }
        _receiving = true;
        var buf = new byte[8192];
        _nat.Loop.Await(_sock.ReceiveAsync(buf.AsMemory(), SocketFlags.None).AsTask(), n =>
        {
            _receiving = false;
            if (_state == State.Closed) return;
            _lastActivity = Environment.TickCount64;
            if (n == 0)
            {
                _hostEof = true;
                Log.Debug($"TCP {Name}: remote closed its side");
            }
            else _sendBuf.Append(buf.AsSpan(0, n));
            TrySend();
            FlushAck();
            StartReceive();
            CheckDone();
        }, ex => { _receiving = false; HostError(ex); });
    }

    void TrySend()
    {
        if (_state != State.Established) return;
        while (true)
        {
            int offset = (int)(_sndNxt - _sndUna);
            int avail = _sendBuf.Count - offset;
            if (avail <= 0) break;
            int wnd = Math.Min(_sndWnd, _cwnd) - offset;
            int n = Math.Min(Math.Min(avail, wnd), EffMss);
            if (n <= 0) break;
            if (_nat.Serial.QueuedBytes > _nat.SerialBacklogLimit) break; // Tick() will continue
            SendData(offset, n);
        }
        if (_hostEof && !_finSent && _sndNxt == _sndUna + (uint)_sendBuf.Count)
        {
            _finSeq = _sndNxt;
            _finSeqValid = true;
            _finSent = true;
            SendSegment(Ip.TcpFin, _finSeq, default, default);
            _sndNxt = _finSeq + 1;
            if (Ip.SeqGt(_sndNxt, _sndMax)) _sndMax = _sndNxt;
        }
    }

    void SendData(int offset, int n)
    {
        bool push = offset + n == _sendBuf.Count;
        SendSegment(push ? Ip.TcpPsh : (byte)0, _sndNxt, _sendBuf.Slice(offset, n), default);
        _sndNxt += (uint)n;
        if (Ip.SeqGt(_sndNxt, _sndMax)) { _bytesToGuest += (int)(_sndNxt - _sndMax); _sndMax = _sndNxt; }
    }

    void SendSegment(byte flags, uint seq, ReadOnlySpan<byte> data, ReadOnlySpan<byte> options)
    {
        int wnd = Window;
        _lastAdvWnd = wnd;
        _ackNeeded = false;
        var pkt = Ip.BuildTcp(_remoteIp, _guestIp, _remotePort, _guestPort, seq, _rcvNxt,
            (byte)(flags | Ip.TcpAck), (ushort)wnd, options, data, _nat.NextIpId());
        _lastSegFrameId = _nat.SendPacket(pkt);
    }

    void FlushAck()
    {
        if (_ackNeeded && _state is State.Established or State.SynReceived) SendSegment(0, _sndNxt, default, default);
    }

    void FastRetransmit()
    {
        // Vintage stacks (Trumpet & co) typically discard out-of-order segments, so resending
        // just the missing one would still leave the rest of the window to an RTO: go back-N.
        Log.Debug($"TCP {Name}: fast retransmit");
        _cwnd = Math.Max(_cwnd / 2, 2 * EffMss);
        _sndNxt = _sndUna;
        if (_finSent && !_finAcked) _finSent = false;
        _rtoStart = -1;
        TrySend();
    }

    void OnRetransmitTimeout()
    {
        if (++_retransmits > MaxRetransmits)
        {
            Log.Info($"TCP {Name}: guest stopped responding, aborting");
            Abort(sendRst: true);
            return;
        }
        Log.Debug($"TCP {Name}: retransmit timeout ({_rtoMs} ms)");
        _rtoMs = Math.Min(_rtoMs * 2, MaxRtoMs);
        _rtoStart = -1;
        _cwnd = EffMss;
        // Go back to the oldest unacknowledged byte and resend from there.
        _sndNxt = _sndUna;
        if (_finSent && !_finAcked) _finSent = false;
        long before = _lastSegFrameId;
        TrySend();
        if (_lastSegFrameId == before && _sendBuf.Count > 0)
            SendData(0, 1); // zero window: probe with one byte
    }

    // ---- timers / teardown ---------------------------------------------------------------

    public void Tick(long now)
    {
        switch (_state)
        {
            case State.SynReceived:
                if (now - _synSentAt >= _rtoMs)
                {
                    if (++_retransmits > 6) { Abort(sendRst: false); return; }
                    _rtoMs = Math.Min(_rtoMs * 2, MaxRtoMs);
                    SendSynAck();
                }
                return;
            case State.Established:
                break;
            default:
                return;
        }

        bool outstanding = _sndNxt != _sndUna || (_sendBuf.Count > 0 && _sndWnd == 0);
        if (!outstanding) _rtoStart = -1;
        else if (_rtoStart < 0)
        {
            // Start the clock only once our last segment actually left the (throttled) serial queue.
            if (_nat.Serial.WrittenId >= _lastSegFrameId) _rtoStart = now;
        }
        else if (now - _rtoStart >= _rtoMs) OnRetransmitTimeout();

        if (_state != State.Established) return;
        TrySend();
        FlushAck();

        long idle = now - _lastActivity;
        if (idle > IdleTimeoutMs || ((_guestFin || _hostEof) && idle > HalfClosedTimeoutMs))
        {
            Log.Debug($"TCP {Name}: idle timeout");
            Abort(sendRst: true);
        }
    }

    void CheckDone()
    {
        if (_state == State.Established && _guestFin && _finAcked && _hostWriteQ.Count == 0)
        {
            Log.Debug($"TCP {Name}: closed ({_bytesFromGuest:N0} bytes up, {_bytesToGuest:N0} bytes down)");
            Close(abortive: false);
        }
    }

    void HostError(Exception ex)
    {
        if (_state == State.Closed) return;
        Log.Debug($"TCP {Name}: host socket error: {Describe(ex)}");
        Abort(sendRst: true);
    }

    public void Abort(bool sendRst)
    {
        if (_state == State.Closed) return;
        if (sendRst && _state != State.Connecting)
            _nat.SendPacket(Ip.BuildTcp(_remoteIp, _guestIp, _remotePort, _guestPort, _sndNxt, _rcvNxt,
                Ip.TcpRst | Ip.TcpAck, 0, default, default, _nat.NextIpId()));
        Close(abortive: true);
    }

    void Close(bool abortive)
    {
        if (_state == State.Closed) return;
        _state = State.Closed;
        _nat.RemoveTcp(this);
        if (_sock == null) return;
        try
        {
            if (abortive) _sock.LingerState = new LingerOption(true, 0);
            _sock.Close();
        }
        catch (Exception) { }
    }

    static string Describe(Exception ex) => ex switch
    {
        SocketException se => se.SocketErrorCode.ToString(),
        OperationCanceledException => "timed out",
        _ => ex.Message,
    };
}
