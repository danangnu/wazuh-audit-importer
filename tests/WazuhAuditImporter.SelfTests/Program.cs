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
cases.Add(("continuous collector defaults accepted", () => new ImportSettings().ValidateCollector()));
cases.Add(("continuous collector poll interval bounded", () => Reject(() => new ImportSettings { CollectorPollSeconds = 1 }.ValidateCollector())));
cases.Add(("continuous collector retry interval bounded", () => Reject(() => new ImportSettings { CollectorRetrySeconds = 1 }.ValidateCollector())));


cases.Add(("worker timing defaults accepted", () => new ImportSettings().Validate()));
cases.Add(("worker lease interval bounded", () => Reject(() => new ImportSettings { WorkerLeaseSeconds = 5 }.Validate())));
cases.Add(("worker retry interval bounded", () => Reject(() => new ImportSettings { WorkerRetrySeconds = 1 }.Validate())));
cases.Add(("continuous worker defaults accepted", () => new ImportSettings().Validate()));
cases.Add(("continuous worker poll interval bounded", () => Reject(() => new ImportSettings { WorkerPollSeconds = 1 }.Validate())));
cases.Add(("continuous worker loop retry bounded", () => Reject(() => new ImportSettings { WorkerLoopRetrySeconds = 1 }.Validate())));
cases.Add(("first worker comparison creates baseline only", () =>
{
    var current = new CandidateSnapshot("1180097", DateTime.UtcNow,
        new Dictionary<string, SnapshotFileState>(StringComparer.OrdinalIgnoreCase)
        {
            ["a.txt"] = new("a.txt", 1, new DateTime(2026, 9, 22, 1, 0, 0, DateTimeKind.Utc))
        });
    var diff = CandidateReconciler.Compare(null, current);
    Assert(diff.IsBaseline && diff.Added.Count == 0 && diff.Removed.Count == 0 && diff.Changed.Count == 0);
}));
cases.Add(("worker comparison detects add remove change", () =>
{
    var t1 = new DateTime(2026, 9, 22, 1, 0, 0, DateTimeKind.Utc);
    var t2 = t1.AddMinutes(1);
    var before = new CandidateSnapshot("1180097", t1,
        new Dictionary<string, SnapshotFileState>(StringComparer.OrdinalIgnoreCase)
        {
            ["same.txt"] = new("same.txt", 10, t1),
            ["changed.txt"] = new("changed.txt", 10, t1),
            ["removed.txt"] = new("removed.txt", 1, t1)
        });
    var after = new CandidateSnapshot("1180097", t2,
        new Dictionary<string, SnapshotFileState>(StringComparer.OrdinalIgnoreCase)
        {
            ["same.txt"] = new("same.txt", 10, t1),
            ["changed.txt"] = new("changed.txt", 11, t2),
            ["added.txt"] = new("added.txt", 1, t2)
        });
    var diff = CandidateReconciler.Compare(before, after);
    Assert(!diff.IsBaseline && diff.Added.SequenceEqual(["added.txt"], StringComparer.OrdinalIgnoreCase));
    Assert(diff.Removed.SequenceEqual(["removed.txt"], StringComparer.OrdinalIgnoreCase));
    Assert(diff.Changed.SequenceEqual(["changed.txt"], StringComparer.OrdinalIgnoreCase));
}));
cases.Add(("worker candidate mismatch rejected", () =>
{
    var a = new CandidateSnapshot("1180097", DateTime.UtcNow, new(StringComparer.OrdinalIgnoreCase));
    var b = new CandidateSnapshot("1180098", DateTime.UtcNow, new(StringComparer.OrdinalIgnoreCase));
    try { CandidateReconciler.Compare(a, b); }
    catch (InvalidOperationException) { return; }
    throw new Exception("Expected candidate mismatch rejection.");
}));


cases.Add(("Solr planner baseline is not required", () =>
{
    var claim = new WorkerClaim(1, "wazuh-lab-pilot-01", "001", "1180097",
        @"C:\Shares-DFS\FastTrack\Candidate\To 1189999\1180097",
        18, 18, 17, 1, Guid.NewGuid().ToString("D"), DateTime.UtcNow.AddMinutes(2));
    var result = new ReconciliationResult("1180097", true, [], [], []);
    var plan = SolrPlanBuilder.Build(claim, result);
    Assert(plan.Operation == "none" && plan.Status == "not_required");
    Assert(plan.AddedCount == 0 && plan.RemovedCount == 0 && plan.ChangedCount == 0);
}));

cases.Add(("Solr planner no-change pass is not required", () =>
{
    var claim = new WorkerClaim(1, "wazuh-lab-pilot-01", "001", "1180097",
        @"C:\Shares-DFS\FastTrack\Candidate\To 1189999\1180097",
        18, 18, 17, 1, Guid.NewGuid().ToString("D"), DateTime.UtcNow.AddMinutes(2));
    var result = new ReconciliationResult("1180097", false, [], [], []);
    var plan = SolrPlanBuilder.Build(claim, result);
    Assert(plan.Operation == "none" && plan.Status == "not_required");
}));

cases.Add(("Solr planner candidate delta becomes reindex plan", () =>
{
    var claim = new WorkerClaim(1, "wazuh-lab-pilot-01", "001", "1180097",
        @"C:\Shares-DFS\FastTrack\Candidate\To 1189999\1180097",
        18, 18, 17, 1, Guid.NewGuid().ToString("D"), DateTime.UtcNow.AddMinutes(2));
    var result = new ReconciliationResult("1180097", false,
        ["added.txt"], ["removed.txt"], ["changed.txt"]);
    var plan = SolrPlanBuilder.Build(claim, result);
    Assert(plan.Operation == "reindex_candidate" && plan.Status == "planned");
    Assert(plan.AddedCount == 1 && plan.RemovedCount == 1 && plan.ChangedCount == 1);
    Assert(plan.PlanJson.Contains("\"execution_supported\":false", StringComparison.Ordinal));
    Assert(plan.PlanJson.Contains("\"collection\":null", StringComparison.Ordinal));
}));

cases.Add(("Solr planner is deterministic for the same worker version", () =>
{
    var claim = new WorkerClaim(1, "wazuh-lab-pilot-01", "001", "1180097",
        @"C:\Shares-DFS\FastTrack\Candidate\To 1189999\1180097",
        18, 18, 17, 1, "00000000-0000-0000-0000-000000000001", DateTime.UtcNow.AddMinutes(2));
    var result = new ReconciliationResult("1180097", false, ["a.txt"], [], []);
    var a = SolrPlanBuilder.Build(claim, result);
    var b = SolrPlanBuilder.Build(claim, result);
    Assert(a.PlanJson == b.PlanJson);
    Assert(a.IdempotencyKey == b.IdempotencyKey && a.IdempotencyKey.Length == 64);
}));

cases.Add(("Solr planner candidate mismatch rejected", () =>
{
    var claim = new WorkerClaim(1, "wazuh-lab-pilot-01", "001", "1180097",
        @"C:\Shares-DFS\FastTrack\Candidate\To 1189999\1180097",
        18, 18, 17, 1, Guid.NewGuid().ToString("D"), DateTime.UtcNow.AddMinutes(2));
    try { SolrPlanBuilder.Build(claim, new ReconciliationResult("1180098", false, [], [], [])); }
    catch (InvalidOperationException) { return; }
    throw new Exception("Expected Solr planner candidate mismatch rejection.");
}));


cases.Add(("Step 9 Solr endpoint defaults accepted", () => new ImportSettings().ValidateSolrReadOnly()));
cases.Add(("Step 9 alternate Solr endpoint rejected", () => Reject(() =>
    new ImportSettings { SolrBaseUrl = "http://192.168.18.23:8983/solr/AlliedSolrCore" }.ValidateSolrReadOnly())));
cases.Add(("FLOSVR01 relative path maps to legacy G drive root", () =>
{
    var mapped = SolrPathMapper.MapRelativeToCanonicalRoot(
        @"G:\Candidate\To 1189999", @"1180097\Resume.pdf");
    Assert(mapped == @"G:\Candidate\To 1189999\1180097\Resume.pdf", mapped);
}));
cases.Add(("legacy Solr ID mirrors active filename algorithm", () =>
{
    Assert(SolrPathMapper.GenerateLegacySolrId(@"G:\Candidate\To 1189999\1180097\Resume.pdf") == "resumepdf");
    Assert(SolrPathMapper.GenerateLegacySolrId(@"G:\Candidate\To 1189999\1180097\A_B-C 1.docx") == "a-bc-1docx");
}));
cases.Add(("legacy filename filter excludes DNI and OCRERROR tokens", () =>
{
    Assert(!SolrPathMapper.LegacyEligibility(@"C:\x\Candidate DNI.pdf", FileAttributes.Normal).Eligible);
    Assert(!SolrPathMapper.LegacyEligibility(@"C:\x\OCRERROR_test.pdf", FileAttributes.Normal).Eligible);
    Assert(SolrPathMapper.LegacyEligibility(@"C:\x\Resume.pdf", FileAttributes.Normal).Eligible);
}));
cases.Add(("Step 9 comparison finds match missing stale and local ID collision", () =>
{
    var schema = new SolrSchemaInfo("id", new Dictionary<string, SolrFieldInfo>(), "test");
    var disk = new List<DiskSolrFile>
    {
        new(@"resume.pdf", @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097\resume.pdf",
            @"G:\Candidate\To 1189999\1180097\resume.pdf", "resumepdf", 10, DateTime.UtcNow, true, null),
        new(@"sub\resume.pdf", @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097\sub\resume.pdf",
            @"G:\Candidate\To 1189999\1180097\sub\resume.pdf", "resumepdf", 11, DateTime.UtcNow, true, null),
        new(@"missing.txt", @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097\missing.txt",
            @"G:\Candidate\To 1189999\1180097\missing.txt", "missingtxt", 1, DateTime.UtcNow, true, null)
    };
    var solr = new List<SolrReadOnlyDocument>
    {
        new("resumepdf", "1180097", @"G:\Candidate\To 1189999\1180097\resume.pdf", null),
        new("oldtxt", "1180097", @"G:\Candidate\To 1189999\1180097\old.txt", null)
    };
    var report = SolrReadOnlyDiscovery.Compare(settings, "1180097",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097", schema, disk, solr);
    Assert(report.Comparisons.Any(x => x.Status == "MATCH" && x.CanonicalPath.EndsWith("resume.pdf", StringComparison.OrdinalIgnoreCase)));
    Assert(report.Comparisons.Any(x => x.Status == "MISSING_IN_SOLR"));
    Assert(report.Comparisons.Any(x => x.Status == "STALE_IN_SOLR"));
    Assert(report.LocalLegacyIdCollisions.Count == 1 && report.LocalLegacyIdCollisions[0].LegacyId == "resumepdf");
}));


cases.Add(("Step 10A missing+stale becomes delete then index", () =>
{
    var schema = new SolrSchemaInfo("id", new Dictionary<string, SolrFieldInfo>(), "test");
    var disk = new List<DiskSolrFile>
    {
        new(@"new.txt", @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097\new.txt",
            @"G:\Candidate\To 1189999\1180097\new.txt", "newtxt", 12,
            new DateTime(2026,9,23,1,2,3,DateTimeKind.Utc), true, null)
    };
    var solr = new List<SolrReadOnlyDocument>
    {
        new("oldpdf", "1180097", @"G:\Candidate\To 1189999\1180097\old.pdf", null)
    };
    var report = SolrReadOnlyDiscovery.Compare(settings, "1180097",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097", schema, disk, solr);
    var target = new SolrMutationTarget(3, settings.SourceInstance, settings.AgentId, "1180097",
        22, "reindex_candidate", "planned", "completed", 22, 22);
    var actions = SolrConcreteActionBuilder.Build(target, report, disk, solr, _ => []);
    Assert(actions.Count == 2);
    Assert(actions[0].ActionType == "delete_document" && actions[0].SolrDocumentId == "oldpdf");
    Assert(actions[1].ActionType == "index_document" && actions[1].SolrDocumentId == "newtxt");
    Assert(actions[0].ActionOrder == 1 && actions[1].ActionOrder == 2);
}));

cases.Add(("Step 10A cross-candidate ID collision blocks planning", () =>
{
    var schema = new SolrSchemaInfo("id", new Dictionary<string, SolrFieldInfo>(), "test");
    var disk = new List<DiskSolrFile>
    {
        new(@"resume.pdf", @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097\resume.pdf",
            @"G:\Candidate\To 1189999\1180097\resume.pdf", "resumepdf", 12,
            DateTime.UtcNow, true, null)
    };
    var report = SolrReadOnlyDiscovery.Compare(settings, "1180097",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097", schema, disk, []);
    var target = new SolrMutationTarget(3, settings.SourceInstance, settings.AgentId, "1180097",
        22, "reindex_candidate", "planned", "completed", 22, 22);
    try
    {
        SolrConcreteActionBuilder.Build(target, report, disk, [], _ =>
            [new SolrReadOnlyDocument("resumepdf", "9999999", @"G:\Candidate\To 9999999\9999999\resume.pdf", null)]);
    }
    catch (SolrConcreteActionException) { return; }
    throw new Exception("Expected cross-candidate legacy ID collision to block planning.");
}));

cases.Add(("Step 10A same-candidate stale ID may be deleted before reindex", () =>
{
    var schema = new SolrSchemaInfo("id", new Dictionary<string, SolrFieldInfo>(), "test");
    var disk = new List<DiskSolrFile>
    {
        new(@"moved\resume.pdf", @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097\moved\resume.pdf",
            @"G:\Candidate\To 1189999\1180097\moved\resume.pdf", "resumepdf", 12,
            DateTime.UtcNow, true, null)
    };
    var old = new SolrReadOnlyDocument("resumepdf", "1180097",
        @"G:\Candidate\To 1189999\1180097\old\resume.pdf", null);
    var solr = new List<SolrReadOnlyDocument> { old };
    var report = SolrReadOnlyDiscovery.Compare(settings, "1180097",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097", schema, disk, solr);
    var target = new SolrMutationTarget(4, settings.SourceInstance, settings.AgentId, "1180097",
        23, "reindex_candidate", "planned", "completed", 23, 23);
    var actions = SolrConcreteActionBuilder.Build(target, report, disk, solr, _ => [old]);
    Assert(actions.Count == 2 && actions[0].ActionType == "delete_document" && actions[1].ActionType == "index_document");
    Assert(actions[0].SolrDocumentId == "resumepdf" && actions[1].SolrDocumentId == "resumepdf");
}));

cases.Add(("Step 10A ID mismatch blocks concrete actions", () =>
{
    var schema = new SolrSchemaInfo("id", new Dictionary<string, SolrFieldInfo>(), "test");
    var disk = new List<DiskSolrFile>
    {
        new(@"a.txt", @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097\a.txt",
            @"G:\Candidate\To 1189999\1180097\a.txt", "atxt", 1, DateTime.UtcNow, true, null)
    };
    var solr = new List<SolrReadOnlyDocument>
    {
        new("different-id", "1180097", @"G:\Candidate\To 1189999\1180097\a.txt", null)
    };
    var report = SolrReadOnlyDiscovery.Compare(settings, "1180097",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097", schema, disk, solr);
    var target = new SolrMutationTarget(3, settings.SourceInstance, settings.AgentId, "1180097",
        22, "reindex_candidate", "planned", "completed", 22, 22);
    try { SolrConcreteActionBuilder.Build(target, report, disk, solr, _ => []); }
    catch (SolrConcreteActionException) { return; }
    throw new Exception("Expected ID mismatch to block planning.");
}));

cases.Add(("Step 10A action identity is deterministic", () =>
{
    var schema = new SolrSchemaInfo("id", new Dictionary<string, SolrFieldInfo>(), "test");
    var disk = new List<DiskSolrFile>
    {
        new(@"a.txt", @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097\a.txt",
            @"G:\Candidate\To 1189999\1180097\a.txt", "atxt", 1,
            new DateTime(2026,9,23,1,0,0,DateTimeKind.Utc), true, null)
    };
    var report = SolrReadOnlyDiscovery.Compare(settings, "1180097",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097", schema, disk, []);
    var target = new SolrMutationTarget(3, settings.SourceInstance, settings.AgentId, "1180097",
        22, "reindex_candidate", "planned", "completed", 22, 22);
    var a = SolrConcreteActionBuilder.Build(target, report, disk, [], _ => []);
    var b = SolrConcreteActionBuilder.Build(target, report, disk, [], _ => []);
    Assert(a.Single().IdempotencyKey == b.Single().IdempotencyKey);
    Assert(a.Single().IdempotencyKey.Length == 64);
}));



cases.Add(("Step 12 changed file forces reindex even when Solr path is MATCH", () =>
{
    var schema = new SolrSchemaInfo("id", new Dictionary<string, SolrFieldInfo>(), "test");
    var disk = new List<DiskSolrFile>
    {
        new(@"WAZUH_SOLR_CONTENT_TEST.txt", @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097\WAZUH_SOLR_CONTENT_TEST.txt",
            @"G:\Candidate\To 1189999\1180097\WAZUH_SOLR_CONTENT_TEST.txt", "wazuh-solr-content-testtxt", 129,
            new DateTime(2026,9,23,4,30,0,DateTimeKind.Utc), true, null)
    };
    var existing = new SolrReadOnlyDocument("wazuh-solr-content-testtxt", "1180097",
        @"G:\Candidate\To 1189999\1180097\WAZUH_SOLR_CONTENT_TEST.txt",
        new DateTimeOffset(new DateTime(2026,9,23,4,0,0,DateTimeKind.Utc)));
    var solr = new List<SolrReadOnlyDocument> { existing };
    var report = SolrReadOnlyDiscovery.Compare(settings, "1180097",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999",
        @"\\FLOSVR01\FastTrack\Candidate\To 1189999\1180097", schema, disk, solr);
    Assert(report.Comparisons.Single().Status == "MATCH");
    var target = new SolrMutationTarget(6, settings.SourceInstance, settings.AgentId, "1180097",
        25, "reindex_candidate", "planned", "completed", 25, 25);
    var changed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "WAZUH_SOLR_CONTENT_TEST.txt" };
    var actions = SolrConcreteActionBuilder.Build(target, report, disk, solr, _ => [existing], changed);
    Assert(actions.Count == 1 && actions[0].ActionType == "index_document");
    Assert(actions[0].Reason == "source_changed" && actions[0].SolrDocumentId == "wazuh-solr-content-testtxt");
}));

cases.Add(("Step 10B delete action builds ready delete-by-id payload", () =>
{
    var action = new SolrStoredAction(1, 3, settings.SourceInstance, settings.AgentId, "1180097", 22,
        1, "delete_document", "planned", "stale_in_solr", "oldpdf",
        @"G:\Candidate\To 1189999\1180097\old.pdf", null, null, null, "x");
    var payload = SolrPayloadBuilder.Build(action, Path.GetTempPath(), new DateTime(2026,9,23,2,0,0,DateTimeKind.Utc));
    Assert(payload.Status == "ready" && payload.Extractor == "solr_delete_by_id");
    Assert(payload.PayloadJson == "{\"delete\":{\"id\":\"oldpdf\"}}");
    Assert(payload.PayloadSha256?.Length == 64);
}));

cases.Add(("Step 10B nonempty txt mirrors legacy ReadAllText and builds Solr document", () =>
{
    var root = Path.Combine(Path.GetTempPath(), "wai-step10b-" + Guid.NewGuid().ToString("N"));
    var candidate = Path.Combine(root, "1180097"); Directory.CreateDirectory(candidate);
    var file = Path.Combine(candidate, "resume.txt"); File.WriteAllText(file, "Hello candidate 1180097");
    var info = new FileInfo(file);
    try
    {
        var action = new SolrStoredAction(2, 3, settings.SourceInstance, settings.AgentId, "1180097", 22,
            2, "index_document", "planned", "missing_in_solr", "resumetxt",
            @"G:\Candidate\To 1189999\1180097\resume.txt", file, (ulong)info.Length, info.LastWriteTimeUtc, "y");
        var payload = SolrPayloadBuilder.Build(action, root, new DateTime(2026,9,23,2,1,2,DateTimeKind.Utc));
        Assert(payload.Status == "ready" && payload.Extractor == "legacy_readalltext");
        Assert(payload.PayloadJson!.Contains("\"dbcandno\":\"1180097\"", StringComparison.Ordinal));
        Assert(payload.PayloadJson.Contains("Hello candidate 1180097", StringComparison.Ordinal));
        Assert(payload.PayloadJson.Contains(@"G:\\Candidate\\To 1189999\\1180097\\resume.txt", StringComparison.Ordinal));
        Assert(payload.ContentCharCount == 23);
    }
    finally { Directory.Delete(root, true); }
}));

cases.Add(("Step 10B empty txt is blocked exactly as legacy doIndexing", () =>
{
    var root = Path.Combine(Path.GetTempPath(), "wai-step10b-" + Guid.NewGuid().ToString("N"));
    var candidate = Path.Combine(root, "1180097"); Directory.CreateDirectory(candidate);
    var file = Path.Combine(candidate, "empty.txt"); File.WriteAllText(file, string.Empty);
    var info = new FileInfo(file);
    try
    {
        var action = new SolrStoredAction(3, 3, settings.SourceInstance, settings.AgentId, "1180097", 22,
            2, "index_document", "planned", "missing_in_solr", "emptytxt",
            @"G:\Candidate\To 1189999\1180097\empty.txt", file, (ulong)info.Length, info.LastWriteTimeUtc, "z");
        var payload = SolrPayloadBuilder.Build(action, root, DateTime.UtcNow);
        Assert(payload.Status == "blocked" && payload.BlockReason == "empty_document_legacy_behavior");
        Assert(payload.PayloadJson is null && payload.SourceFileSha256?.Length == 64);
    }
    finally { Directory.Delete(root, true); }
}));

cases.Add(("Step 10B PDF blocks rather than silently changing the legacy extractor", () =>
{
    var root = Path.Combine(Path.GetTempPath(), "wai-step10b-" + Guid.NewGuid().ToString("N"));
    var candidate = Path.Combine(root, "1180097"); Directory.CreateDirectory(candidate);
    var file = Path.Combine(candidate, "resume.pdf"); File.WriteAllBytes(file, [1,2,3]);
    var info = new FileInfo(file);
    try
    {
        var action = new SolrStoredAction(4, 3, settings.SourceInstance, settings.AgentId, "1180097", 22,
            2, "index_document", "planned", "missing_in_solr", "resumepdf",
            @"G:\Candidate\To 1189999\1180097\resume.pdf", file, (ulong)info.Length, info.LastWriteTimeUtc, "q");
        var payload = SolrPayloadBuilder.Build(action, root, DateTime.UtcNow);
        Assert(payload.Status == "blocked" && payload.Extractor == "legacy_pdfbox_1_8_2_not_ported");
        Assert(payload.BlockReason == "legacy_extractor_not_ported");
    }
    finally { Directory.Delete(root, true); }
}));

cases.Add(("Step 10B source metadata change blocks stale payload generation", () =>
{
    var root = Path.Combine(Path.GetTempPath(), "wai-step10b-" + Guid.NewGuid().ToString("N"));
    var candidate = Path.Combine(root, "1180097"); Directory.CreateDirectory(candidate);
    var file = Path.Combine(candidate, "a.txt"); File.WriteAllText(file, "changed");
    var info = new FileInfo(file);
    try
    {
        var action = new SolrStoredAction(5, 3, settings.SourceInstance, settings.AgentId, "1180097", 22,
            2, "index_document", "planned", "missing_in_solr", "atxt",
            @"G:\Candidate\To 1189999\1180097\a.txt", file, 999, info.LastWriteTimeUtc, "r");
        var payload = SolrPayloadBuilder.Build(action, root, DateTime.UtcNow);
        Assert(payload.Status == "blocked" && payload.BlockReason == "source_changed_since_action_plan");
    }
    finally { Directory.Delete(root, true); }
}));



cases.Add(("Step 11 accepts an intact ready reviewed payload", () =>
{
    var action = new SolrStoredAction(9, 5, settings.SourceInstance, settings.AgentId, "1180097", 24,
        1, "delete_document", "planned", "stale_in_solr", "oldpdf",
        @"G:\Candidate\To 1189999\1180097\old.pdf", null, null, null, "key");
    var json = "{\"delete\":{\"id\":\"oldpdf\"}}";
    var hash = LegacyContentExtractor.HexSha256(System.Text.Encoding.UTF8.GetBytes(json));
    var payload = new SolrPayloadSpec(9, 5, "delete_document", "ready", "solr_delete_by_id",
        json, hash, null, null, null, null, null, null, DateTime.UtcNow);
    SolrExecutionSafety.ValidateReadyItem(new SolrExecutionItem(action, payload));
}));

cases.Add(("Step 11 rejects a blocked payload before execution", () =>
{
    var action = new SolrStoredAction(10, 5, settings.SourceInstance, settings.AgentId, "1180097", 24,
        1, "index_document", "planned", "missing_in_solr", "atxt",
        @"G:\Candidate\To 1189999\1180097\a.txt", @"C:\tmp\a.txt", 0, DateTime.UtcNow, "key2");
    var payload = new SolrPayloadSpec(10, 5, "index_document", "blocked", "legacy_readalltext",
        null, null, null, null, 0, 0, DateTime.UtcNow, "empty_document_legacy_behavior", DateTime.UtcNow);
    try { SolrExecutionSafety.ValidateReadyItem(new SolrExecutionItem(action, payload)); }
    catch (SolrExecutionException) { return; }
    throw new Exception("Expected blocked Step 11 payload rejection.");
}));

cases.Add(("Step 11 detects reviewed payload drift", () =>
{
    var root = Path.Combine(Path.GetTempPath(), "wai-step11-" + Guid.NewGuid().ToString("N"));
    var candidate = Path.Combine(root, "1180097"); Directory.CreateDirectory(candidate);
    var file = Path.Combine(candidate, "a.txt"); File.WriteAllText(file, "original");
    var info = new FileInfo(file);
    try
    {
        var action = new SolrStoredAction(11, 5, settings.SourceInstance, settings.AgentId, "1180097", 24,
            1, "index_document", "planned", "missing_in_solr", "atxt",
            @"G:\Candidate\To 1189999\1180097\a.txt", file, (ulong)info.Length, info.LastWriteTimeUtc, "key3");
        var generatedAt = new DateTime(2026,9,23,3,0,0,DateTimeKind.Utc);
        var reviewed = SolrPayloadBuilder.Build(action, root, generatedAt);
        var item = new SolrExecutionItem(action, reviewed);
        File.WriteAllText(file, "modified-content");
        var now = SolrPayloadBuilder.Build(action, root, generatedAt);
        try { SolrExecutionSafety.ValidateCurrentPayload(item, now); }
        catch (SolrExecutionException) { return; }
        throw new Exception("Expected Step 11 payload drift rejection.");
    }
    finally { Directory.Delete(root, true); }
}));

cases.Add(("Step 11 detects current Solr action-plan drift", () =>
{
    var action = new SolrStoredAction(12, 5, settings.SourceInstance, settings.AgentId, "1180097", 24,
        1, "delete_document", "planned", "stale_in_solr", "oldpdf",
        @"G:\Candidate\To 1189999\1180097\old.pdf", null, null, null, "stable-key");
    var json = "{\"delete\":{\"id\":\"oldpdf\"}}";
    var payload = new SolrPayloadSpec(12, 5, "delete_document", "ready", "solr_delete_by_id",
        json, LegacyContentExtractor.HexSha256(System.Text.Encoding.UTF8.GetBytes(json)), null, null, null, null, null, null, DateTime.UtcNow);
    var stored = new List<SolrExecutionItem> { new(action, payload) };
    var current = new List<SolrConcreteActionSpec>
    {
        new(1, "delete_document", "planned", "stale_in_solr", "different-id",
            @"G:\Candidate\To 1189999\1180097\old.pdf", null, null, null, null, "different-key")
    };
    try { SolrExecutionSafety.ValidateCurrentActionPlan(stored, current); }
    catch (SolrExecutionException) { return; }
    throw new Exception("Expected Step 11 action-plan drift rejection.");
}));


cases.Add(("Step 12 orchestration defaults accepted", () => new ImportSettings().Validate()));
cases.Add(("Step 12 orchestration poll interval bounded", () => Reject(() => new ImportSettings { OrchestratorPollSeconds = 1 }.Validate())));
cases.Add(("Step 12 orchestration worker drain bounded", () => Reject(() => new ImportSettings { OrchestratorMaxWorkerItemsPerCycle = 0 }.Validate())));

cases.Add(("Step 12 decision is idle before any mutation exists", () =>
{
    var d = PipelineDecision.Decide(null);
    Assert(d.Disposition == PipelineMutationDisposition.Idle);
}));

cases.Add(("Step 12 decision waits for worker version convergence", () =>
{
    var snap = new PipelineMutationSnapshot(20, "1180097", 30, "reindex_candidate", "planned",
        "pending", 31, 30, 0, 0, 0, 0);
    var d = PipelineDecision.Decide(snap);
    Assert(d.Disposition == PipelineMutationDisposition.WaitingForWorker);
}));

cases.Add(("Step 12 decision requests concrete actions", () =>
{
    var snap = new PipelineMutationSnapshot(21, "1180097", 31, "reindex_candidate", "planned",
        "completed", 31, 31, 0, 0, 0, 0);
    var d = PipelineDecision.Decide(snap);
    Assert(d.Disposition == PipelineMutationDisposition.NeedsActions);
}));

cases.Add(("Step 12 decision requests missing payloads", () =>
{
    var snap = new PipelineMutationSnapshot(22, "1180097", 32, "reindex_candidate", "planned",
        "completed", 32, 32, 2, 0, 1, 0);
    var d = PipelineDecision.Decide(snap);
    Assert(d.Disposition == PipelineMutationDisposition.NeedsPayloads && snap.MissingPayloadCount == 1);
}));

cases.Add(("Step 12 decision blocks any blocked payload", () =>
{
    var snap = new PipelineMutationSnapshot(23, "1180097", 33, "reindex_candidate", "planned",
        "completed", 33, 33, 2, 0, 1, 1);
    var d = PipelineDecision.Decide(snap);
    Assert(d.Disposition == PipelineMutationDisposition.BlockedPayload);
}));

cases.Add(("Step 12 decision exposes ready mutation for manual approval", () =>
{
    var snap = new PipelineMutationSnapshot(24, "1180097", 34, "reindex_candidate", "planned",
        "completed", 34, 34, 2, 0, 2, 0);
    var d = PipelineDecision.Decide(snap);
    Assert(d.Disposition == PipelineMutationDisposition.ReadyForApproval);
}));

cases.Add(("Step 12 decision halts on unresolved failed execution", () =>
{
    var snap = new PipelineMutationSnapshot(25, "1180097", 35, "reindex_candidate", "failed",
        "completed", 35, 35, 2, 2, 2, 0);
    var d = PipelineDecision.Decide(snap);
    Assert(d.Disposition == PipelineMutationDisposition.HaltedExecution);
}));

cases.Add(("Step 12 decision treats applied mutation as complete", () =>
{
    var snap = new PipelineMutationSnapshot(26, "1180097", 36, "reindex_candidate", "applied",
        "completed", 36, 36, 2, 2, 2, 0);
    var d = PipelineDecision.Decide(snap);
    Assert(d.Disposition == PipelineMutationDisposition.Complete);
}));

var failed = 0;
foreach (var (name, run) in cases)
{
    try { run(); Console.WriteLine("PASS: " + name); }
    catch (Exception e) { failed++; Console.Error.WriteLine("FAIL: " + name + " -- " + e.Message); }
}
Console.WriteLine($"\nSelf-tests: {cases.Count - failed}/{cases.Count} passed; {failed} failed.");
Console.WriteLine("These are parser/scope/worker-diff/Solr-plan/Step9/Step10A/Step10B/Step11/Step12 safety tests only. No MariaDB connection, Solr connection, or SQL was executed.");
return failed == 0 ? 0 : 1;
