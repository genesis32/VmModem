using System.Text;

namespace VmModem;

public enum LogLevel { Error = 0, Warn = 1, Info = 2, Debug = 3, Trace = 4, Dump = 5 }

/// <summary>
/// Tiny thread-safe logger: colored console output at <see cref="Level"/>, plus a log
/// file that always records at least Trace detail (every packet), so a session can be
/// diagnosed afterwards without having re-run it with -v.
/// </summary>
public static class Log
{
    const long MaxFileBytes = 50L * 1024 * 1024;

    static readonly object Sync = new();
    static StreamWriter? _file;

    /// <summary>Console verbosity.</summary>
    public static LogLevel Level { get; set; } = LogLevel.Info;

    static LogLevel FileLevel => Level > LogLevel.Trace ? Level : LogLevel.Trace;

    public static string? FilePath { get; private set; }

    /// <summary>Default log location: %LOCALAPPDATA%\VmModem\vmmodem.log.</summary>
    public static string DefaultFilePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VmModem", "vmmodem.log");

    public static void OpenFile(string path)
    {
        FilePath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        OpenWriter();
    }

    static void OpenWriter()
    {
        // Keep one previous generation: vmmodem.log -> vmmodem.1.log
        var info = new FileInfo(FilePath!);
        if (info.Exists && info.Length > MaxFileBytes)
            File.Move(FilePath!, Path.ChangeExtension(FilePath!, ".1.log"), overwrite: true);
        _file = new StreamWriter(new FileStream(FilePath!, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete), Encoding.UTF8)
            { AutoFlush = true };
        _file.WriteLine();
        _file.WriteLine($"===== VmModem log started {DateTime.Now:yyyy-MM-dd HH:mm:ss} (pid {Environment.ProcessId}) =====");
    }

    public static bool IsEnabled(LogLevel level) => level <= Level || (_file != null && level <= FileLevel);

    public static void Error(string msg) => Write(LogLevel.Error, msg);
    public static void Warn(string msg) => Write(LogLevel.Warn, msg);
    public static void Info(string msg) => Write(LogLevel.Info, msg);
    public static void Debug(string msg) => Write(LogLevel.Debug, msg);
    public static void Trace(string msg) => Write(LogLevel.Trace, msg);

    public static void Write(LogLevel level, string msg)
    {
        if (!IsEnabled(level)) return;
        lock (Sync)
        {
            string time = DateTime.Now.ToString("HH:mm:ss.fff ");
            if (level <= Level)
            {
                var old = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(time);
                Console.ForegroundColor = level switch
                {
                    LogLevel.Error => ConsoleColor.Red,
                    LogLevel.Warn => ConsoleColor.Yellow,
                    LogLevel.Info => ConsoleColor.Gray,
                    LogLevel.Debug => ConsoleColor.Cyan,
                    LogLevel.Trace => ConsoleColor.DarkGray,
                    _ => ConsoleColor.DarkYellow,
                };
                Console.WriteLine(msg);
                Console.ForegroundColor = old;
            }
            if (_file != null && level <= FileLevel)
            {
                try
                {
                    _file.WriteLine($"{time}{level.ToString().ToUpperInvariant(),-5} {msg}");
                    if (_file.BaseStream.Length > MaxFileBytes)
                    {
                        _file.Dispose();
                        OpenWriter();
                    }
                }
                catch (IOException) { }
            }
        }
    }

    /// <summary>Hex + ASCII dump of raw serial data (shown with -vvv).</summary>
    public static void Hex(string title, ReadOnlySpan<byte> data)
    {
        if (!IsEnabled(LogLevel.Dump)) return;
        var sb = new StringBuilder($"{title} ({data.Length} bytes)");
        for (int off = 0; off < data.Length; off += 16)
        {
            var row = data.Slice(off, Math.Min(16, data.Length - off));
            sb.Append("\n    ").Append(off.ToString("X4")).Append("  ");
            for (int i = 0; i < 16; i++)
                sb.Append(i < row.Length ? row[i].ToString("X2") + " " : "   ");
            sb.Append(' ');
            foreach (byte b in row) sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
        }
        Write(LogLevel.Dump, sb.ToString());
    }
}
