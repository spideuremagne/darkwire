using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Service;
using System.Text.Json;

static AppState ReadPolicy(string path)
{
    var fullPath = Path.GetFullPath(path);
    if (!File.Exists(fullPath)) throw new FileNotFoundException("The requested policy file does not exist.", fullPath);
    if (new FileInfo(fullPath).Length > ServiceProtocol.MaximumMessageBytes) throw new InvalidDataException("The policy file is too large.");
    return StateStore.Read(fullPath);
}

static StreamReader OpenCsv(string path) => path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)
    ? new(new System.IO.Compression.GZipStream(File.OpenRead(path), System.IO.Compression.CompressionMode.Decompress))
    : File.OpenText(path);

try
{
    if (args.SequenceEqual(new[] { "--service" })) { ServiceHost.Run(); return 0; }
    if (args.Length == 5 && args[0] == "--build-geoip")
    {
        // Build time: converts DB-IP Lite CSVs, plain or gzipped, into the compact database the installer ships.
        using var country = OpenCsv(args[1]); using var asn = OpenCsv(args[2]);
        var database = GeoIpDatabase.Build(country, asn, args[3]);
        using (var output = new FileStream(args[4], FileMode.Create, FileAccess.Write, FileShare.None)) database.Write(output);
        Console.WriteLine($"GeoIP {database.Release}: {database.Count:N0} ranges written to {Path.GetFullPath(args[4])}.");
        return 0;
    }
    if (args.Length == 4 && args[0] == "--build-geoip-cities")
    {
        // Build time: converts DB-IP's City Lite CSV, plain or gzipped, into the city data the installer ships for the app.
        using var city = OpenCsv(args[1]);
        var cities = GeoIpCities.Build(city, args[2]);
        using (var output = new FileStream(args[3], FileMode.Create, FileAccess.Write, FileShare.None)) cities.Write(output);
        Console.WriteLine($"GeoIP cities {cities.Release}: {cities.Count:N0} ranges in {cities.Places:N0} places written to {Path.GetFullPath(args[3])}.");
        return 0;
    }
    if (args.SequenceEqual(new[] { "--self-test" })) return ServiceSelfTests.Run();
    // Windows Installer custom actions, run as SYSTEM from the installed directory.
    if (args.Length > 0 && args[0] is "--install" or "--uninstall" or "--rollback") return ServiceSetup.Run(args);
    if (args.SequenceEqual(new[] { "--audit-firewall" }))
    {
        // Read-only: translates the current Windows rule store and resolves it natively without opening WFP.
        var snapshot = new WindowsFirewallControl().Read();
        var network = new NetworkEnvironment().Capture();
        var plan = FilterCompiler.Compile(new() { Mode = FirewallMode.BlockNew, Rules = snapshot.Rules }, network: network);
        // The same policy after an administrator accepts every reduced import.
        var consented = new AppState { Mode = FirewallMode.BlockNew, Rules = snapshot.Rules.Select(r =>
        {
            var copy = JsonSerializer.Deserialize<FirewallRule>(JsonSerializer.Serialize(r, StateStore.JsonOptions), StateStore.JsonOptions)!;
            copy.NarrowingAccepted = true; return copy;
        }).ToList() };
        var afterReview = FilterCompiler.Compile(consented, network: network);
        var native = afterReview.CanApply ? WfpConditions.Preflight(afterReview) : [];
        var outcomes = snapshot.Rules.GroupBy(r => r.Import ?? ImportOutcome.Exact).OrderBy(g => g.Key)
            .Select(g => new { Outcome = g.Key, RuleCount = g.Count(), EnabledCount = g.Count(r => r.Enabled) });
        var reasons = snapshot.Rules.Where(r => r.Import is not (null or ImportOutcome.Exact)).GroupBy(r => r.ImportWarning ?? "")
            .OrderByDescending(g => g.Count()).Select(g => new { Reason = g.Key, RuleCount = g.Count(), EnabledCount = g.Count(r => r.Enabled) });
        var review = snapshot.Rules.Where(r => RuleEnforcement.NeedsConsent(r) || r.Enabled && r.Import == ImportOutcome.Refused)
            .Select(r => new { r.WindowsRuleId, r.ApplicationName, r.Import, r.Action, r.ImportWarning });
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            snapshot.Profiles, snapshot.InboundAllowed, snapshot.OutboundAllowed, RuleCount = snapshot.Rules.Count, EnabledCount = snapshot.Rules.Count(r => r.Enabled),
            Outcomes = outcomes, NeedsReview = review, Reasons = reasons.Take(40),
            FiltersAfterReview = afterReview.Filters.Count, CanTakeOverWithoutReview = snapshot.Errors.Count == 0 && plan.CanApply && WfpConditions.Preflight(plan).Count == 0,
            CanTakeOverAfterReview = snapshot.Errors.Count == 0 && afterReview.CanApply && native.Count == 0,
            Errors = snapshot.Errors.Concat(afterReview.Errors).Concat(native).Take(20).ToArray()
        }, StateStore.JsonOptions));
        return 0;
    }
    if (args.Length is 1 or 2 && args[0] == "--compare-mpssvc")
    {
        // Read-only and elevated: compares Windows Firewall's own WFP filters with Darkwire's translation, rule by rule.
        var snapshot = new WindowsFirewallControl().Read();
        if (snapshot.Profiles.Values.Any(enabled => !enabled)) Console.Error.WriteLine("Some Windows Firewall profiles are disabled; their rules have no Windows filters to compare.");
        var comparisons = TranslationComparison.Compare(snapshot.Rules, new NetworkEnvironment().Capture());
        var report = JsonSerializer.Serialize(new
        {
            Generated = DateTimeOffset.UtcNow, snapshot.Profiles, Verdicts = comparisons.GroupBy(c => c.Verdict).ToDictionary(g => g.Key, g => g.Count()),
            ReadErrors = snapshot.Errors, Rules = comparisons
        }, StateStore.JsonOptions);
        var output = args.Length == 2 ? Path.GetFullPath(args[1]) : Path.GetFullPath("darkwire-translation-compare.json");
        File.WriteAllText(output, report);
        Console.WriteLine($"{comparisons.Count} enabled rule groups compared: " + string.Join(", ", comparisons.GroupBy(c => c.Verdict).Select(g => $"{g.Key} {g.Count()}")) + ". Report: " + output);
        return 0;
    }
    if (args.SequenceEqual(new[] { "--policy" }))
    {
        // The enforced policy alone, in the form --apply and --apply-vpn read back.
        var answer = await ServiceClient.SendAsync(new("policy"));
        if (!answer.Success || answer.Policy is null) { Console.Error.WriteLine(answer.Message); return 1; }
        Console.WriteLine(JsonSerializer.Serialize(answer.Policy, StateStore.JsonOptions));
        return 0;
    }
    ServiceRequest? request = args.Length switch
    {
        1 when args[0] == "--status" => new("status"),
        1 when args[0] == "--restore" => new("restore"),
        2 when args[0] is "--preflight" or "--takeover" => new(args[0][2..], ReadPolicy(args[1])),
        3 when args[0] == "--apply" && long.TryParse(args[2], out var revision) => new("apply", ReadPolicy(args[1]), ExpectedRevision: revision),
        // A policy's VPN profiles, default route and local network setting alone, as the VPN page applies them.
        2 when args[0] == "--apply-vpn" && ReadPolicy(args[1]) is var vpn => new("apply-vpn", Routes: new(vpn.VpnProfiles, vpn.DefaultOutboundVpnProfileId, vpn.LocalNetworkBypassesVpn)),
        _ => null
    };
    if (request is null)
    {
        Console.WriteLine("Darkwire.Service --status | --policy | --preflight policy.json | --takeover policy.json | --apply policy.json expectedRevision | --apply-vpn policy.json | --restore | --self-test | --audit-firewall | --compare-mpssvc [report.json] | --install | --uninstall | --rollback | --build-geoip country.csv[.gz] asn.csv[.gz] YYYY-MM out.dat | --build-geoip-cities city.csv[.gz] YYYY-MM out.dat");
        return 2;
    }
    var response = await ServiceClient.SendAsync(request);
    Console.WriteLine(JsonSerializer.Serialize(response, StateStore.JsonOptions)); return response.Success ? 0 : 1;
}
catch (Exception error) { Console.Error.WriteLine(error.Message); return 1; }
