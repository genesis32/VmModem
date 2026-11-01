using System.Diagnostics;

namespace VmModem;

/// <summary>
/// Output queue towards the VM's serial port. A dedicated thread drains it,
/// optionally pacing the bytes to a modem line rate so the guest's emulated UART
/// isn't overrun. Every enqueued chunk gets an increasing id; <see cref="WrittenId"/>
/// tells the TCP layer when a segment has actually left (to start its RTO clock).
/// </summary>
public sealed class SerialOut : IDisposable
{
    readonly Stream _stream;
    readonly double _bytesPerSecond; // 0 = unlimited
    readonly Queue<(byte[] Data, long Id)> _queue = new();
    readonly object _lock = new();
    readonly Thread _thread;
    long _nextId;
    long _writtenId;
    long _queuedBytes;
    bool _stopped;

    public event Action<Exception>? Failed;

    public SerialOut(Stream stream, int baud)
    {
        _stream = stream;
        _bytesPerSecond = baud > 0 ? baud / 10.0 : 0; // 8N1: 10 bits per byte
        _thread = new Thread(Run) { IsBackground = true, Name = "SerialOut" };
        _thread.Start();
    }

    public long WrittenId => Interlocked.Read(ref _writtenId);
    public long QueuedBytes => Interlocked.Read(ref _queuedBytes);
    public long LastId { get { lock (_lock) return _nextId; } }
    public double BytesPerSecond => _bytesPerSecond;

    public long Enqueue(byte[] data)
    {
        Log.Hex("modem -> VM", data);
        lock (_lock)
        {
            if (_stopped) return _nextId;
            long id = ++_nextId;
            _queue.Enqueue((data, id));
            Interlocked.Add(ref _queuedBytes, data.Length);
            Monitor.Pulse(_lock);
            return id;
        }
    }

    public void Enqueue(string text) => Enqueue(System.Text.Encoding.ASCII.GetBytes(text));

    /// <summary>Drops everything not yet written (used on hang-up).</summary>
    public void Clear()
    {
        lock (_lock)
        {
            while (_queue.Count > 0)
            {
                var (data, id) = _queue.Dequeue();
                Interlocked.Add(ref _queuedBytes, -data.Length);
                Interlocked.Exchange(ref _writtenId, id);
            }
        }
    }

    void Run()
    {
        var clock = Stopwatch.StartNew();
        double nextFree = 0; // seconds on 'clock' when the line is free again
        // Pace in chunks of ~1/64 s worth of data.
        int chunk = _bytesPerSecond > 0 ? Math.Max(16, (int)(_bytesPerSecond / 64)) : 65536;
        try
        {
            while (true)
            {
                byte[] data; long id;
                lock (_lock)
                {
                    while (_queue.Count == 0 && !_stopped) Monitor.Wait(_lock);
                    if (_stopped) return;
                    (data, id) = _queue.Dequeue();
                }

                for (int off = 0; off < data.Length; off += chunk)
                {
                    int n = Math.Min(chunk, data.Length - off);
                    if (_bytesPerSecond > 0)
                    {
                        double now = clock.Elapsed.TotalSeconds;
                        if (nextFree < now) nextFree = now;
                        double wait = nextFree - now;
                        if (wait > 0.002) Thread.Sleep(TimeSpan.FromSeconds(wait));
                        nextFree += n / _bytesPerSecond;
                    }
                    _stream.Write(data, off, n);
                    Interlocked.Add(ref _queuedBytes, -n);
                }
                _stream.Flush();
                Interlocked.Exchange(ref _writtenId, id);
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
            lock (_lock) _stopped = true;
            Failed?.Invoke(ex);
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _stopped = true;
            Monitor.PulseAll(_lock);
        }
    }
}
