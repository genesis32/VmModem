using System.Collections.Concurrent;

namespace VmModem;

/// <summary>
/// Single-threaded work queue. Each modem session runs all of its protocol state
/// (modem, PPP, NAT) on one of these, so none of that code needs locking. Socket
/// completions and timers post back onto the loop.
/// </summary>
public sealed class EventLoop
{
    readonly BlockingCollection<Action> _queue = new();
    readonly CancellationTokenSource _cts = new();
    int _threadId;

    public bool IsLoopThread => Environment.CurrentManagedThreadId == _threadId;
    public CancellationToken Stopping => _cts.Token;

    public void Post(Action action)
    {
        if (_cts.IsCancellationRequested) return;
        try { _queue.Add(action); }
        catch (InvalidOperationException) { } // completed
    }

    /// <summary>Runs <paramref name="action"/> on the loop after a delay. Dispose the result to cancel.</summary>
    public IDisposable Schedule(TimeSpan delay, Action action)
    {
        var handle = new TimerHandle();
        handle.Timer = new Timer(_ => Post(() => { if (!handle.Cancelled) action(); }),
            null, delay, Timeout.InfiniteTimeSpan);
        return handle;
    }

    /// <summary>Runs <paramref name="action"/> on the loop periodically.</summary>
    public IDisposable Every(TimeSpan period, Action action)
    {
        var handle = new TimerHandle();
        int queued = 0;
        handle.Timer = new Timer(_ =>
        {
            // Don't pile up ticks if the loop is busy.
            if (Interlocked.Exchange(ref queued, 1) == 1) return;
            Post(() => { queued = 0; if (!handle.Cancelled) action(); });
        }, null, period, period);
        return handle;
    }

    /// <summary>Awaits <paramref name="task"/> and delivers its outcome on the loop thread.</summary>
    public void Await<T>(Task<T> task, Action<T> onResult, Action<Exception> onError)
    {
        task.ContinueWith(t =>
        {
            if (t.IsCompletedSuccessfully) { var r = t.Result; Post(() => onResult(r)); }
            else { var ex = t.Exception?.GetBaseException() ?? new OperationCanceledException(); Post(() => onError(ex)); }
        }, TaskScheduler.Default);
    }

    public void Await(Task task, Action onDone, Action<Exception> onError)
    {
        task.ContinueWith(t =>
        {
            if (t.IsCompletedSuccessfully) Post(onDone);
            else { var ex = t.Exception?.GetBaseException() ?? new OperationCanceledException(); Post(() => onError(ex)); }
        }, TaskScheduler.Default);
    }

    public void Run()
    {
        _threadId = Environment.CurrentManagedThreadId;
        try
        {
            foreach (var action in _queue.GetConsumingEnumerable(_cts.Token))
            {
                try { action(); }
                catch (Exception ex) { Log.Error($"Internal error: {ex}"); }
            }
        }
        catch (OperationCanceledException) { }
    }

    public void Stop()
    {
        _cts.Cancel();
        _queue.CompleteAdding();
    }

    sealed class TimerHandle : IDisposable
    {
        public Timer? Timer;
        public volatile bool Cancelled;
        public void Dispose() { Cancelled = true; Timer?.Dispose(); }
    }
}
