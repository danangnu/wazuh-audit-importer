using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace WazuhAuditImporter;

public sealed class ImportSettings
{
    public string DatabaseHost { get; set; } = "127.0.0.1";
    public uint DatabasePort { get; set; } = 3306;
    public string DatabaseName { get; set; } = "wazuh_audit_poc";
    public string ExpectedDatabaseServer { get; set; } = "MGMTNB08";
    public string? DatabaseUser { get; set; }
    public string SourceInstance { get; set; } = "wazuh-lab-pilot-01";
    public string AgentId { get; set; } = "001";
    public string AgentName { get; set; } = "FLOSVR01";
    public string CandidateRoot { get; set; } = @"C:\Shares-DFS\FastTrack\Candidate\To 1189999";
    public string[] CandidateIds { get; set; } = ["1180097"];

    // Step 4 collector is intentionally confined to the local SSH tunnel.
    public string IndexerBaseUrl { get; set; } = "https://127.0.0.1:19200";
    public string IndexerIndexPattern { get; set; } = "wazuh-alerts-4.x-*";
    public bool IndexerAllowUntrustedCertificate { get; set; } = true;
    public int IndexerTimeoutSeconds { get; set; } = 30;
    public int IndexerInitialLookbackMinutes { get; set; } = 1440;
    public int IndexerOverlapSeconds { get; set; } = 600;
    public int IndexerPageSize { get; set; } = 200;
    public int IndexerMaxPages { get; set; } = 20;
    public string CollectorStreamKey { get; set; } = "flosvr01-fim-pilot";
    public int CollectorPollSeconds { get; set; } = 10;
    public int CollectorRetrySeconds { get; set; } = 15;

    // Step 6 candidate worker. The accessible root is supplied explicitly at runtime;
    // these settings control claim/retry timing only.
    public int WorkerLeaseSeconds { get; set; } = 120;
    public int WorkerRetrySeconds { get; set; } = 30;

    public static ImportSettings Load(string? path)
    {
        var settings = path is null ? new ImportSettings() :
            JsonSerializer.Deserialize<ImportSettings>(File.ReadAllText(path), new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
            }) ?? throw new FormatException("The configuration must contain an object.");
        settings.Validate();
        return settings;
    }

    public void Validate()
    {
        if (DatabaseHost != "127.0.0.1" || DatabasePort == 0 || DatabasePort > 65535)
            throw new FormatException("This pilot requires DatabaseHost=127.0.0.1 and a valid port.");
        if (DatabaseName != "wazuh_audit_poc")
            throw new FormatException("This pilot writes only to wazuh_audit_poc.");
        if (string.IsNullOrWhiteSpace(ExpectedDatabaseServer))
            throw new FormatException("ExpectedDatabaseServer is required.");
        if (string.IsNullOrEmpty(SourceInstance) ||
            !Regex.IsMatch(SourceInstance, @"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z"))
            throw new FormatException("SourceInstance must be 1-64 ASCII letters/digits, '.', '_' or '-'.");
        if (string.IsNullOrEmpty(AgentId) || !Regex.IsMatch(AgentId, @"\A[0-9]{1,32}\z") ||
            string.IsNullOrWhiteSpace(AgentName) || AgentName.Length > 191)
            throw new FormatException("AgentId and AgentName are required.");
        if (string.IsNullOrEmpty(CandidateRoot) ||
            !Regex.IsMatch(CandidateRoot, @"\A[A-Za-z]:\\[^\r\n]+\z") ||
            CandidateRoot.Contains('/') || CandidateRoot.Any(char.IsControl) ||
            CandidateRoot[3..].Split('\\').Any(p => p is "" or "." or ".." || p.Contains(':')))
            throw new FormatException("CandidateRoot must be an absolute Windows directory without traversal.");
        if (CandidateIds is null || CandidateIds.Length == 0 ||
            CandidateIds.Any(id => id is null || !Regex.IsMatch(id, @"\A[0-9]{1,32}\z")))
            throw new FormatException("Set an explicit nonempty list of allowed CandidateIds.");
        ValidateCollector();
        if (WorkerLeaseSeconds is < 30 or > 1800 || WorkerRetrySeconds is < 5 or > 3600)
            throw new FormatException("Worker timing settings are outside pilot limits.");
    }

    public void ValidateWorker(string workerRoot, string stateDirectory)
    {
        if (string.IsNullOrWhiteSpace(workerRoot) || !Path.IsPathFullyQualified(workerRoot))
            throw new FormatException("Worker root must be an explicit fully-qualified local or UNC path.");
        if (string.IsNullOrWhiteSpace(stateDirectory))
            throw new FormatException("Worker state directory is required.");
        var fullState = Path.GetFullPath(stateDirectory);
        if (!Path.IsPathFullyQualified(fullState))
            throw new FormatException("Worker state directory must resolve to a fully-qualified path.");
        if (CandidateIds.Length != 1 || CandidateIds[0] != "1180097")
            throw new FormatException("Step 6 pilot remains limited to candidate 1180097.");
    }

    public void ValidateCollector()
    {
        if (!Uri.TryCreate(IndexerBaseUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || uri.Host != "127.0.0.1" || uri.Port != 19200)
            throw new FormatException("This pilot collector requires IndexerBaseUrl=https://127.0.0.1:19200 through the local SSH tunnel.");
        if (IndexerIndexPattern != "wazuh-alerts-4.x-*")
            throw new FormatException("Unexpected IndexerIndexPattern for this pilot.");
        if (IndexerTimeoutSeconds is < 5 or > 300 || IndexerInitialLookbackMinutes is < 1 or > 10080 ||
            IndexerOverlapSeconds is < 0 or > 3600 || IndexerPageSize is < 1 or > 500 || IndexerMaxPages is < 1 or > 100 ||
            CollectorPollSeconds is < 5 or > 300 || CollectorRetrySeconds is < 5 or > 300)
            throw new FormatException("Collector numeric settings are outside pilot limits.");
        if (!Regex.IsMatch(CollectorStreamKey ?? string.Empty, @"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z"))
            throw new FormatException("CollectorStreamKey is invalid.");
    }
}
