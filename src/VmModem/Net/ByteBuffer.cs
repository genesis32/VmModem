namespace VmModem.Net;

/// <summary>Growable FIFO byte buffer with cheap discard from the front.</summary>
public sealed class ByteBuffer
{
    byte[] _buf = new byte[4096];
    int _start, _count;

    public int Count => _count;

    public void Append(ReadOnlySpan<byte> data)
    {
        if (_start + _count + data.Length > _buf.Length)
        {
            if (_count + data.Length <= _buf.Length / 2)
            {
                Buffer.BlockCopy(_buf, _start, _buf, 0, _count); // compact
            }
            else
            {
                var n = new byte[Math.Max(_buf.Length * 2, (_count + data.Length) * 2)];
                Buffer.BlockCopy(_buf, _start, n, 0, _count);
                _buf = n;
            }
            _start = 0;
        }
        data.CopyTo(_buf.AsSpan(_start + _count));
        _count += data.Length;
    }

    public void Discard(int n)
    {
        n = Math.Min(n, _count);
        _start += n;
        _count -= n;
        if (_count == 0) _start = 0;
    }

    public ReadOnlySpan<byte> Slice(int offset, int length) => _buf.AsSpan(_start + offset, length);
}
