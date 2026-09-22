using System.Text.Json;
using System.Text.Json.Nodes;
using WazuhAuditImporter;

var raw = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "wazuh-delete-sample.json"));
var source = JsonNode.Parse(raw)!["_source"]!.ToJsonString();
var cases = new List<(string Name, Action Run)>();
var settings = new ImportSettings();

void Assert(bool value, string message = "Assertion failed") { if (!value) throw new Exception(message); }
void Reject(Action action)
{
    try { action(); }
    catch (Exception e) when (e is FormatException or JsonException) { return; }
    throw new Exception("Expected malformed-input rejection.");
}
string Change(Action<JsonNode> edit)
{
    var obj = JsonNode.Parse(source)!; edit(obj); return obj.ToJsonString();
}
NormalizedAlert Parse(string input) => AlertParser.Parse(input, settings).Alert ?? throw new Exception("Unexpected ignore.");
void Ignored(string input) => Assert(AlertParser.Parse(input, settings).Alert is null);

cases.Add(("wrapped export is accepted", () => Assert(Parse(raw).EventType == "deleted")));
cases.Add(("unwrapped source is accepted", () => Assert(Parse(source).WazuhEventId == "1790045703.1555358")));
cases.Add(("leading-zero agent ID retained", () => Assert(Parse(raw).AgentId == "001")));
cases.Add(("exact manager name retained", () => Assert(Parse(raw).ManagerName == "wahzuh-lab")));
cases.Add(("candidate 1180097 extracted", () => Assert(Parse(raw).CandidateId == "1180097")));
cases.Add(("owner is not actor", () => Assert(Parse(raw) is { FileOwnerName: "Administrators", ActorName: null, ActorProcess: null })));
cases.Add(("explicit who-data actor only", () =>
{
    var input = Change(x => x["syscheck"]!["audit"] = JsonNode.Parse("""{"user":{"name":"test-operator"},"process":{"name":"test.exe"}}"""));
    Assert(Parse(input) is { ActorName: "test-operator", ActorProcess: "test.exe" });
}));
cases.Add(("UTC timestamp, not file mtime", () => Assert(Parse(raw).EventTimeUtc ==
    new DateTime(2026, 9, 22, 2, 55, 3, 623, DateTimeKind.Utc))));
cases.Add(("nonzero timezone conversion", () => Assert(
    AlertParser.ParseTimestamp("2026-09-22T10:55:03.623+0800") == Parse(raw).EventTimeUtc)));
cases.Add(("timestamp without zone rejected", () => Reject(() => AlertParser.ParseTimestamp("2026-09-22T02:55:03.623"))));
cases.Add(("microseconds retained", () => Assert(
    AlertParser.ParseTimestamp("2026-09-22T02:55:03.1234567Z").Ticks % TimeSpan.TicksPerSecond == 1234560)));
cases.Add(("reported size parsed from string", () => Assert(Parse(raw).ReportedSizeBytes == 128UL)));
cases.Add(("raw payload preserved exactly", () => Assert(Parse(raw).RawJson == raw)));
cases.Add(("wrapper and whitespace do not cause duplicate conflict", () => Assert(AlertParser.SameSourcePayload(raw, source))));
cases.Add(("source property order ignored", () =>
{
    var obj = JsonNode.Parse(source)!.AsObject();
    var reordered = new JsonObject();
    foreach (var p in obj.Reverse()) reordered[p.Key] = p.Value?.DeepClone();
    Assert(AlertParser.SameSourcePayload(raw, reordered.ToJsonString()));
}));
cases.Add(("changed source content conflicts", () => Assert(!AlertParser.SameSourcePayload(raw,
    Change(x => x["syscheck"]!["event"] = "added")))));
cases.Add(("nonessential enrichment difference remains same normalized event", () =>
{
    var changed = Change(x => x["rule"]!["description"] = "Alternate presentation text");
    Assert(AlertParser.SameNormalizedPayload(raw, changed, settings));
}));
cases.Add(("material normalized difference conflicts", () =>
{
    var changed = Change(x => x["syscheck"]!["event"] = "added");
    Assert(!AlertParser.SameNormalizedPayload(raw, changed, settings));
}));
cases.Add(("unrelated sudo match ignored", () => Ignored(JsonSerializer.Serialize(new
{
    id = "unrelated", location = "journald", full_log = "sudo grep wazuh_poc_20260922_103746_552",
    agent = new { id = "000", name = "wazuh-lab" }
}))));
cases.Add(("wrong agent ignored", () => Ignored(Change(x => x["agent"]!["id"] = "000"))));
cases.Add(("wrong candidate ignored", () => Ignored(Change(x => x["syscheck"]!["path"] =
    @"c:\shares-dfs\fasttrack\candidate\to 1189999\1180098\other.txt"))));
cases.Add(("root-prefix collision ignored", () => Ignored(Change(x => x["syscheck"]!["path"] =
    @"c:\shares-dfs\fasttrack\candidate\to 11899990\1180097\other.txt"))));
cases.Add(("traversal rejected", () => Reject(() => Parse(Change(x => x["syscheck"]!["path"] =
    @"c:\shares-dfs\fasttrack\candidate\to 1189999\1180097\..\other.txt")))));
cases.Add(("unsupported event ignored", () => Ignored(Change(x => x["syscheck"]!["event"] = "renamed"))));
cases.Add(("numeric agent ID rejected", () => Reject(() => Parse(Change(x => x["agent"]!["id"] = 1)))));
cases.Add(("duplicate JSON keys rejected", () => Reject(() => Parse("{\"agent\":{},\"agent\":{}}"))));
cases.Add(("invalid hash rejected", () => Reject(() => Parse(Change(x => x["syscheck"]!["sha256_after"] = "invalid")))));
cases.Add(("negative size rejected", () => Reject(() => Parse(Change(x => x["syscheck"]!["size_after"] = "-1")))));
cases.Add(("array input rejected", () => Reject(() => Parse("[]"))));
cases.Add(("added event accepted", () => Assert(Parse(Change(x => x["syscheck"]!["event"] = "added")).EventType == "added")));
cases.Add(("modified event accepted", () => Assert(Parse(Change(x => x["syscheck"]!["event"] = "modified")).EventType == "modified")));
cases.Add(("nonlocal database target rejected", () => Reject(() => new ImportSettings { DatabaseHost = "192.168.100.20" }.Validate())));
cases.Add(("application database target rejected", () => Reject(() => new ImportSettings { DatabaseName = "seek_uuid_test_trackitlive" }.Validate())));
cases.Add(("collector local SSH tunnel accepted", () => new ImportSettings().ValidateCollector()));
cases.Add(("collector remote indexer rejected", () => Reject(() => new ImportSettings { IndexerBaseUrl = "https://172.30.90.252:9200" }.ValidateCollector())));
cases.Add(("collector non-HTTPS rejected", () => Reject(() => new ImportSettings { IndexerBaseUrl = "http://127.0.0.1:19200" }.ValidateCollector())));
cases.Add(("collector page size bounded", () => Reject(() => new ImportSettings { IndexerPageSize = 1000 }.ValidateCollector())));

var failed = 0;
foreach (var (name, run) in cases)
{
    try { run(); Console.WriteLine("PASS: " + name); }
    catch (Exception e) { failed++; Console.Error.WriteLine("FAIL: " + name + " -- " + e.Message); }
}
Console.WriteLine($"\nSelf-tests: {cases.Count - failed}/{cases.Count} passed; {failed} failed.");
Console.WriteLine("These are parser/scope tests only. No MariaDB connection or SQL was executed.");
return failed == 0 ? 0 : 1;
