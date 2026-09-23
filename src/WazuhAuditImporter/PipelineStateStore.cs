using System.Text.Json;

namespace WazuhAuditImporter;

public static class PipelineStateStore
{
    public const string StateFileName = "step12-pipeline-state.json";
    public const string LockFileName = "step12-pipeline.lock";

    public static string Save(string stateDirectory, PipelineLocalState state)
    {
        var dir = Path.GetFullPath(stateDirectory);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, StateFileName);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, path, overwrite: true);
        return path;
    }

    public static PipelineProcessLock AcquireProcessLock(string stateDirectory)
    {
        var dir = Path.GetFullPath(stateDirectory);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, LockFileName);
        try
        {
            var stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            stream.SetLength(0);
            using var writer = new StreamWriter(stream, System.Text.Encoding.UTF8, 1024, leaveOpen: true);
            writer.WriteLine($"pid={Environment.ProcessId}");
            writer.WriteLine($"started_utc={DateTime.UtcNow:O}");
            writer.Flush();
            stream.Flush(flushToDisk: true);
            stream.Position = 0;
            return new PipelineProcessLock(path, stream);
        }
        catch (IOException ex)
        {
            throw new InvalidOperationException(
                $"Another Step 12 orchestrator appears to hold the process lock '{path}'. Stop the other instance before starting another.", ex);
        }
    }
}

public sealed class PipelineProcessLock : IDisposable
{
    private FileStream? _stream;
    public string Path { get; }

    internal PipelineProcessLock(string path, FileStream stream)
    {
        Path = path;
        _stream = stream;
    }

    public void Dispose()
    {
        var stream = Interlocked.Exchange(ref _stream, null);
        if (stream is null) return;
        try { stream.Dispose(); } catch { }
    }
}
