using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WazuhAuditImporter;

public static class AlertParser
{
    public const int MaximumInputBytes = 4 * 1024 * 1024;

    public static ParseResult Parse(string rawJson, ImportSettings settings)
    {
        settings.Validate();
        if (Encoding.UTF8.GetByteCount(rawJson) > MaximumInputBytes)
            throw new FormatException("Input is larger than the 4 MiB single-event limit.");
        using var doc = JsonDocument.Parse(rawJson, new JsonDocumentOptions { MaxDepth = 64 });
        EnsureUniqueProperties(doc.RootElement);
        var source = Unwrap(doc.RootElement);
        if (!source.TryGetProperty("syscheck", out var sc) || sc.ValueKind != JsonValueKind.Object)
            return new(null, "Not a structured FIM event (no syscheck object).");
        if (OptionalString(source, "location") != "syscheck")
            return new(null, "Not a syscheck source event.");
        var eventType = RequiredString(sc, "event");
        if (eventType is not ("added" or "modified" or "deleted"))
            return new(null, "Unsupported FIM event type.");
        var agent = RequiredObject(source, "agent");
        var agentId = RequiredString(agent, "id");
        var agentName = RequiredString(agent, "name");
        if (agentId != settings.AgentId ||
            !agentName.Equals(settings.AgentName, StringComparison.OrdinalIgnoreCase))
            return new(null, "Agent is outside the configured pilot scope.");
        var rule = RequiredObject(source, "rule");
        if (!rule.TryGetProperty("groups", out var groups) || groups.ValueKind != JsonValueKind.Array ||
            !groups.EnumerateArray().Any(x => x.ValueKind == JsonValueKind.String && x.GetString() == "syscheck"))
            return new(null, "Rule groups do not identify a syscheck event.");

        var path = RequiredString(sc, "path");
        CheckText(path, "syscheck.path", 65535, textColumn: true);
        if (path.Any(char.IsControl) || path.Contains('/'))
            throw new FormatException("A Windows FIM path cannot contain controls or forward slashes in this pilot.");
        var prefix = settings.CandidateRoot + "\\";
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return new(null, "Path is outside the configured candidate root.");
        var segments = path[prefix.Length..].Split('\\');
        if (segments.Any(p => p is "" or "." or ".." || p.Contains(':') || p.EndsWith('.') || p.EndsWith(' ')))
            throw new FormatException("Invalid or ambiguous path components; event rejected.");
        var candidateId = segments[0];
        if (!Regex.IsMatch(candidateId, @"\A[0-9]{1,32}\z") || !settings.CandidateIds.Contains(candidateId))
            return new(null, "Candidate is outside the explicit pilot allowlist.");

        var eventId = RequiredString(source, "id");
        CheckAscii(eventId, "id", 64);
        CheckAscii(agentId, "agent.id", 32);
        CheckText(agentName, "agent.name", 191);
        var managerName = RequiredString(RequiredObject(source, "manager"), "name");
        CheckText(managerName, "manager.name", 191);
        var ip = OptionalString(agent, "ip");
        if (ip is not null) CheckAscii(ip, "agent.ip", 45);
        var mode = OptionalString(sc, "mode");
        if (mode is not null) CheckAscii(mode, "syscheck.mode", 32);
        var ruleId = OptionalString(rule, "id");
        if (ruleId is not null) CheckAscii(ruleId, "rule.id", 32);
        var levelValue = OptionalUnsigned(rule, "level");
        if (levelValue is not null && levelValue.Value > ushort.MaxValue) throw new FormatException("Rule level exceeds SMALLINT UNSIGNED.");
        var owner = OptionalString(sc, "uname_after") ?? OptionalString(sc, "uname_before");
        if (owner is not null) CheckText(owner, "file owner", 255);
        string? actor = null;
        string? process = null;
        if (sc.TryGetProperty("audit", out var audit) && audit.ValueKind == JsonValueKind.Object)
        {
            if (audit.TryGetProperty("user", out var user) && user.ValueKind == JsonValueKind.Object)
                actor = OptionalString(user, "name");
            if (audit.TryGetProperty("process", out var proc) && proc.ValueKind == JsonValueKind.Object)
                process = OptionalString(proc, "name");
        }
        if (actor is not null) CheckText(actor, "actor name", 255);
        if (process is not null) CheckText(process, "actor process", 65535, textColumn: true);
        var sha = OptionalString(sc, "sha256_after") ?? OptionalString(sc, "sha256_before");
        if (sha is not null && !Regex.IsMatch(sha, @"\A[0-9a-fA-F]{64}\z"))
            throw new FormatException("Reported SHA256 must contain exactly 64 hexadecimal characters.");

        return new(new NormalizedAlert
        {
            SourceInstance = settings.SourceInstance,
            WazuhEventId = eventId, AgentId = agentId, AgentName = agentName, AgentIp = ip,
            ManagerName = managerName, CandidateId = candidateId,
            CandidateFolder = settings.CandidateRoot + "\\" + candidateId,
            EventType = eventType, DetectionMode = mode, RuleId = ruleId,
            RuleLevel = levelValue is null ? null : (ushort)levelValue.Value,
            EventTimeUtc = ParseTimestamp(RequiredString(source, "timestamp")),
            SourcePath = path, FileOwnerName = owner, ActorName = actor, ActorProcess = process,
            ReportedSizeBytes = OptionalUnsigned(sc, "size_after") ?? OptionalUnsigned(sc, "size_before"),
            ReportedSha256 = sha, RawJson = rawJson
        }, null);
    }

    public static DateTime ParseTimestamp(string text)
    {
        // Wazuh uses +0000; DateTimeOffset accepts the normalized +00:00 form.
        if (!Regex.IsMatch(text, @"T.*(?:[zZ]|[+-][0-9]{2}:?[0-9]{2})\z"))
            throw new FormatException("Alert timestamp must include Z or an explicit UTC offset.");
        text = Regex.Replace(text, @"([+-][0-9]{2})([0-9]{2})\z", "$1:$2");
        if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dto) ||
            dto.UtcDateTime.Year < 1000)
            throw new FormatException("Alert timestamp is invalid or outside MariaDB DATETIME range.");
        // MariaDB DATETIME(6): truncate 100 ns ticks to microseconds deterministically.
        var utc = dto.UtcDateTime;
        return new DateTime(utc.Ticks - utc.Ticks % 10, DateTimeKind.Utc);
    }

    public static bool SameSourcePayload(string a, string b)
    {
        // Ignore the indexer wrapper, JSON indentation and property order only.
        // Any differing source value remains a conflict; never silently overwrite.
        return CanonicalSource(a).AsSpan().SequenceEqual(CanonicalSource(b));
    }

    public static bool SameNormalizedPayload(string a, string b, ImportSettings settings)
    {
        // A dashboard export and a direct Indexer hit can carry different nonessential
        // wrapper/enrichment fields for the same Wazuh event. Duplicate safety is based
        // on the normalized fields that this importer actually persists and acts on.
        // Material differences (agent, path, event type, timestamp, hashes, etc.) still
        // conflict. The first raw_json is preserved unchanged in the audit table.
        var left = Parse(a, settings).Alert;
        var right = Parse(b, settings).Alert;
        if (left is null || right is null) return false;
        return (left with { RawJson = string.Empty }) ==
               (right with { RawJson = string.Empty });
    }

    private static byte[] CanonicalSource(string input)
    {
        using var doc = JsonDocument.Parse(input);
        EnsureUniqueProperties(doc.RootElement);
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output))
            WriteCanonical(writer, Unwrap(doc.RootElement));
        return output.ToArray();
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            writer.WriteStartObject();
            foreach (var prop in value.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
            {
                writer.WritePropertyName(prop.Name);
                WriteCanonical(writer, prop.Value);
            }
            writer.WriteEndObject();
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            writer.WriteStartArray();
            foreach (var item in value.EnumerateArray()) WriteCanonical(writer, item);
            writer.WriteEndArray();
        }
        else value.WriteTo(writer);
    }

    private static JsonElement Unwrap(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
            throw new FormatException("Supply one event object, not an array or search-results batch.");
        return root.TryGetProperty("_source", out var source)
            ? source.ValueKind == JsonValueKind.Object ? source : throw new FormatException("_source is not an object.")
            : root;
    }

    private static void EnsureUniqueProperties(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in value.EnumerateObject())
            {
                if (!names.Add(p.Name)) throw new FormatException("JSON contains a duplicate property name.");
                EnsureUniqueProperties(p.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) EnsureUniqueProperties(item);
    }

    private static JsonElement RequiredObject(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var child) && child.ValueKind == JsonValueKind.Object
            ? child : throw new FormatException($"Missing or invalid object: {name}.");

    private static string RequiredString(JsonElement parent, string name) =>
        OptionalString(parent, name) is { Length: > 0 } text ? text :
            throw new FormatException($"Missing or empty string: {name}.");

    private static string? OptionalString(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String) throw new FormatException($"{name} must be a string.");
        return value.GetString();
    }

    private static ulong? OptionalUnsigned(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        var text = value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            _ => null
        };
        if (text is null || !ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var number))
            throw new FormatException($"{name} must be a nonnegative integer.");
        return number;
    }

    private static void CheckText(string text, string field, int max, bool textColumn = false)
    {
        if (text.Contains('\0') || (textColumn ? Encoding.UTF8.GetByteCount(text) : text.Length) > max)
            throw new FormatException($"{field} exceeds storage limits or contains NUL.");
    }
    private static void CheckAscii(string text, string field, int max)
    {
        if (text.Length == 0 || text.Length > max || text.Any(c => c < 33 || c > 126))
            throw new FormatException($"{field} must be a nonempty printable ASCII value up to {max} characters.");
    }
}
