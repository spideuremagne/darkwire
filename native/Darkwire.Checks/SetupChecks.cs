using Darkwire.Core;
using Darkwire.Engine;
using Darkwire.Host;
using System.Text.Json;

/// <summary>One-click setup stops at the first step that fails or needs the user, and takes over only when nothing does.</summary>
internal static class SetupChecks
{
    /// <summary>A scripted service: the status and stored policy given, preflight merging Windows' rules into the draft.</summary>
    private sealed class FakeService
    {
        public ServiceStatus? Status = new(true, false, "Inactive", FirewallMode.Learning, 0, true, "Windows Firewall is in control.");
        public AppState Stored = new();
        public List<FirewallRule> Windows = [Inherited("Core Networking", ImportOutcome.Exact)];
        public List<string> Errors = [];
        public bool RefuseTakeover;
        public List<string> Requests = [];
        public AppState? TakenOver;

        public Task<ServiceResponse> Send(ServiceRequest request)
        {
            Requests.Add(request.Command);
            return Task.FromResult(request.Command switch
            {
                "status" => Status is { } status ? new ServiceResponse(true, status.Message, status) : throw new TimeoutException("The operation has timed out."),
                "policy" => new ServiceResponse(true, "Authoritative service policy.", Status, Clone(Stored)),
                "preflight" => Preflight(request.Policy!),
                "takeover" => Takeover(request.Policy!),
                _ => new ServiceResponse(false, "Unexpected request " + request.Command)
            });
        }

        private ServiceResponse Preflight(AppState draft)
        {
            // As the service merges: a draft's copy of a Windows rule keeps its consent, and the rest come fresh from Windows.
            var candidate = Clone(draft);
            var copies = candidate.Rules.Where(r => r.WindowsRuleId is not null).ToDictionary(r => r.WindowsRuleId!);
            candidate.Rules = [.. candidate.Rules.Where(r => r.WindowsRuleId is null), .. Windows.Select(r => copies.GetValueOrDefault(r.WindowsRuleId!) ?? Clone(r))];
            List<string> errors = [.. Errors, .. candidate.Rules.Where(RuleEnforcement.NeedsConsent).Select(r => r.ApplicationName + ": accept the broader block.")];
            return new(errors.Count == 0, errors.Count == 0 ? "Policy can be translated and installed." : "Takeover refused; Windows Firewall is unchanged.", Status, candidate, Errors: errors);
        }

        private ServiceResponse Takeover(AppState candidate)
        {
            if (RefuseTakeover) return new(false, "Takeover refused: Windows Firewall rules changed.", Status);
            TakenOver = candidate; Status = Status! with { Active = true, Phase = "Active" };
            return new(true, "Darkwire is enforcing persistent policy.", Status, Clone(candidate));
        }
    }

    private static T Clone<T>(T value) => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value, StateStore.JsonOptions), StateStore.JsonOptions)!;

    private static FirewallRule Inherited(string name, ImportOutcome outcome, RuleAction action = RuleAction.Allow) =>
        new() { ApplicationName = name, Path = "System", Action = action, WindowsRuleId = name.Replace(' ', '-'), Import = outcome, Source = "Windows Firewall" };

    private static FirewallRule Own(string name) => new() { ApplicationName = name, Path = $@"C:\Apps\{name}.exe", Action = RuleAction.Allow };

    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool value, string reason = "Setup invariant failed.") { if (!value) throw new Exception(reason); }
        // Runs setup against the fake service, adopting policies into the draft the way the editor does.
        static (SetupOutcome Outcome, Setup Setup, List<AppState> Adopted) Attempt(FakeService service, AppState draft, bool elevated = true)
        {
            var setup = new Setup(service.Send); List<AppState> adopted = [];
            var outcome = setup.RunAsync(draft, elevated, (policy, _) =>
            {
                adopted.Add(policy); draft.Mode = policy.Mode; draft.Rules = policy.Rules; draft.Blocklists = policy.Blocklists; return draft;
            }).GetAwaiter().GetResult();
            return (outcome, setup, adopted);
        }
        static SetupState State(Setup setup, int step) => setup.Steps[step].State;

        check("The Overview alert says Darkwire isn't enforcing only when the service says so, and a missed read or two changes nothing", () =>
        {
            static ServiceStatus Status(bool active, string phase = "Inactive") => new(true, active, active ? "Active" : phase, FirewallMode.Learning, 0, true, "Interrupted takeover.");
            var watch = new ServiceWatch();
            Expect(SetupAlert.For(watch, elevated: false) is null, "An alert showed before the service was read.");
            watch.Answered(Status(true));
            Expect(SetupAlert.For(watch, false) is null, "An enforcing service raised the alert.");
            // The pipe answers one request at a time; a read can time out while the service is busy.
            watch.Missed("The operation has timed out."); watch.Missed("The operation has timed out.");
            Expect(watch.Status is { Active: true } && SetupAlert.For(watch, false) is null, "Two missed reads hid an enforcing service.");
            watch.Missed("The operation has timed out.");
            Expect(watch.Offline && SetupAlert.For(watch, false) is { Title: "The Darkwire service isn't answering", Action: SetupAction.CheckAgain } offline &&
                offline.Detail.Contains("timed out") && !offline.Title.Contains("isn't enforcing"), "A silent service was reported as not enforcing.");
            watch.Answered(Status(false));
            Expect(SetupAlert.For(watch, true) is { Title: "Darkwire isn't enforcing yet", Action: SetupAction.SetUp } elevated && !elevated.Detail.Contains("administrator"));
            Expect(SetupAlert.For(watch, false) is { Action: SetupAction.RestartElevated } unelevated && unelevated.Detail.Contains("administrator rights"));
            watch.Answered(Status(false, "Prepared"));
            Expect(SetupAlert.For(watch, false) is { Title: "Darkwire needs recovery", Detail: "Interrupted takeover.", Action: SetupAction.CheckAgain });
            var silent = new ServiceWatch(); silent.Missed("The service is not running.");
            Expect(silent.Offline && SetupAlert.For(silent, true) is { Action: SetupAction.CheckAgain }, "A service that never answered raised no alert.");
            Expect(SetupAlert.For(new ServiceWatch(), true, demo: true) is { Title: "Darkwire isn't enforcing yet" });
            // A demo shows the installed app, which always runs as administrator, even from a session that doesn't.
            Expect(SetupAlert.For(new ServiceWatch(), false, demo: true) is { Action: SetupAction.SetUp } shown && !shown.Detail.Contains("administrator"), "A demo's alert asked for administrator rights.");
        });
        check("Setup stops when the service does not answer, or a takeover waits for recovery", () =>
        {
            var silent = new FakeService { Status = null };
            var (outcome, setup, _) = Attempt(silent, new());
            Expect(outcome == SetupOutcome.Stopped && State(setup, Setup.Service) == SetupState.Failed && setup.Steps[Setup.Service].Detail.Contains("timed out"), "An unreachable service was not reported.");
            Expect(silent.Requests is ["status"] && setup.Steps.Skip(1).All(s => s.State == SetupState.Waiting));
            var recovering = new FakeService { Status = new(true, false, "Prepared", FirewallMode.Learning, 0, true, "Interrupted takeover.") };
            (outcome, setup, _) = Attempt(recovering, new());
            Expect(outcome == SetupOutcome.Stopped && State(setup, Setup.Service) == SetupState.Failed && setup.Steps[Setup.Service].Detail.Contains("recovery"), "A takeover waiting for recovery was not reported.");
        });
        check("Without administrator rights setup checks the service, then stops before changing anything", () =>
        {
            var service = new FakeService { Stored = new() { Rules = [Own("Earlier")] } };
            var (outcome, setup, adopted) = Attempt(service, new(), elevated: false);
            Expect(outcome == SetupOutcome.Stopped && State(setup, Setup.Service) == SetupState.Done && State(setup, Setup.Administrator) == SetupState.NeedsYou);
            Expect(service.Requests is ["status"] && adopted.Count == 0, "Setup went on without administrator rights.");
        });
        check("When Darkwire already enforces policy, setup loads it and takes nothing over", () =>
        {
            var service = new FakeService { Status = new(true, true, "Active", FirewallMode.BlockNew, 900, true, "Enforcing."), Stored = new() { Mode = FirewallMode.BlockNew, Rules = [Own("Learned")] } };
            var (outcome, setup, adopted) = Attempt(service, new());
            Expect(outcome == SetupOutcome.AlreadyActive && adopted.Single().Rules.Single().ApplicationName == "Learned");
            Expect(State(setup, Setup.Policy) == SetupState.Done && new[] { Setup.Administrator, Setup.Validate, Setup.Review, Setup.TakeOver }.All(s => State(setup, s) == SetupState.Skipped));
            Expect(!service.Requests.Contains("preflight") && !service.Requests.Contains("takeover"));
        });
        check("Setup takes over at once when nothing needs consent and every enabled rule comes from Windows", () =>
        {
            var service = new FakeService(); service.Windows.Add(Inherited("Cast to Device", ImportOutcome.Unenforced));
            var (outcome, setup, adopted) = Attempt(service, new());
            Expect(outcome == SetupOutcome.TookOver && service.Requests is ["status", "policy", "preflight", "takeover"], "Setup did not take over: " + string.Join(", ", service.Requests));
            Expect(service.TakenOver!.Rules.Count == 2 && setup.Steps.All(s => s.State == SetupState.Done));
            Expect(setup.Steps[Setup.Validate].Detail.Contains("2 Windows rules inherited, 1 of them left out or reduced"), setup.Steps[Setup.Validate].Detail);
            Expect(adopted.Single().Rules.Count == 2, "The enforced policy did not reach the editor.");
        });
        check("An earlier service policy comes back only into a draft with no rules of its own", () =>
        {
            var service = new FakeService { Stored = new() { Mode = FirewallMode.BlockNew, Rules = [Own("Earlier"), Own("Older")] } };
            var draft = new AppState();
            var (outcome, setup, adopted) = Attempt(service, draft);
            Expect(adopted.Count == 1 && draft.Mode == FirewallMode.BlockNew && setup.Steps[Setup.Policy].Detail.Contains("Restored"), "The earlier policy was not restored.");
            // Its rules are not from Windows, so the review opens before anything is taken over.
            Expect(outcome == SetupOutcome.NeedsReview && setup.PendingReview!.Added.Count == 2 && service.TakenOver is null);
            var edited = new AppState { Rules = [Own("Mine")] };
            (outcome, setup, adopted) = Attempt(new FakeService { Stored = service.Stored }, edited);
            Expect(adopted.Count == 0 && edited.Rules.Single().ApplicationName == "Mine" && setup.PendingReview!.Added.Single().ApplicationName == "Mine", "An edited draft was overwritten.");
        });
        check("A broader block waits for the review, validation errors stop setup, and a refused takeover is reported", () =>
        {
            var consent = new FakeService(); consent.Windows.Add(Inherited("Block sharing", ImportOutcome.Narrowed, RuleAction.Deny));
            var (outcome, setup, _) = Attempt(consent, new());
            Expect(outcome == SetupOutcome.NeedsReview && State(setup, Setup.Review) == SetupState.NeedsYou && setup.Steps[Setup.Review].Detail.StartsWith("1 broader block needs your consent"));
            // The review preflights the policy consent would produce, and nothing is taken over without the user.
            Expect(consent.Requests.Count(r => r == "preflight") == 2 && setup.PendingReview is { Final.Success: true, Consent: [{ NarrowingAccepted: true }] } && consent.TakenOver is null);
            setup.Reviewed(null);
            Expect(State(setup, Setup.Review) == SetupState.NeedsYou && setup.PendingReview is null);
            setup.Reviewed(new(true, "Darkwire is enforcing persistent policy."));
            Expect(State(setup, Setup.Review) == SetupState.Done && State(setup, Setup.TakeOver) == SetupState.Done);
            var invalid = new FakeService { Errors = ["Initial takeover requires Learning, Block new, or Lockdown."] };
            (outcome, setup, _) = Attempt(invalid, new());
            Expect(outcome == SetupOutcome.Stopped && State(setup, Setup.Validate) == SetupState.Failed && setup.Steps[Setup.Validate].Detail.Contains("requires Learning") && !invalid.Requests.Contains("takeover"));
            var refused = new FakeService { RefuseTakeover = true };
            (outcome, setup, _) = Attempt(refused, new());
            Expect(outcome == SetupOutcome.Stopped && State(setup, Setup.TakeOver) == SetupState.Failed && setup.Steps[Setup.TakeOver].Detail.Contains("rules changed"));
        });
    }
}
