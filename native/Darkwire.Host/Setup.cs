using Darkwire.Engine;

namespace Darkwire.Host;

/// <summary>The names the app gives the firewall modes.</summary>
public static class Modes
{
    public static string Name(FirewallMode mode) => mode switch { FirewallMode.Open => "Allow all", FirewallMode.Learning => "Learning", FirewallMode.BlockNew => "Block new", _ => "Lockdown" };
}

public enum SetupState { Waiting, Running, Done, Skipped, NeedsYou, Failed }

/// <summary>One step of setup and what it found.</summary>
public sealed record SetupStep(string Title, SetupState State = SetupState.Waiting, string Detail = "");

public enum SetupOutcome { Stopped, AlreadyActive, NeedsReview, TookOver }

/// <summary>
/// What a takeover would install: the draft merged with Windows' rules as the service prepared it, consent marked on the
/// broader blocks that need it, and the service's verdict on that exact policy.
/// </summary>
public sealed record TakeoverReview(AppState Candidate, WindowsDefaults? Defaults, IReadOnlyList<FirewallRule> Consent, ServiceResponse Final)
{
    public IReadOnlyList<FirewallRule> Imported => [.. Candidate.Rules.Where(r => r.WindowsRuleId is not null)];
    /// <summary>Windows rules Darkwire leaves out or reduces. Nothing is widened, but their features stop working.</summary>
    public IReadOnlyList<FirewallRule> OutOfScope =>
        [.. Imported.Where(r => r.Enabled && (r.Import == ImportOutcome.Unenforced || r.Import == ImportOutcome.Narrowed && r.Action != RuleAction.Deny))];
    /// <summary>Enabled rules that did not come from Windows. Any program running as the user can write the draft, so these are always shown.</summary>
    public IReadOnlyList<FirewallRule> Added => [.. Candidate.Rules.Where(r => r.Enabled && r.WindowsRuleId is null)];
    /// <summary>The user looks first when a block needs consent, rules of their own are enabled, or the policy cannot be installed.</summary>
    public bool NeedsUser => Consent.Count > 0 || Added.Count > 0 || !Final.Success;

    /// <summary>
    /// Preflights the draft against a fresh Windows import, then the exact policy consent would produce, so the errors left
    /// are the real blockers. Review is null when the service refused the draft itself.
    /// </summary>
    public static async Task<(TakeoverReview? Review, ServiceResponse First)> PrepareAsync(AppState draft, Func<ServiceRequest, Task<ServiceResponse>> send)
    {
        var first = await send(new("preflight", draft));
        if (first.Policy is not { } candidate) return (null, first);
        // Only broader blocks need consent. Rules Darkwire leaves out or reduces never allow more than Windows did.
        var consent = candidate.Rules.Where(RuleEnforcement.NeedsConsent).ToList();
        foreach (var rule in consent) rule.NarrowingAccepted = true;
        var final = consent.Count == 0 ? first : await send(new("preflight", candidate));
        return (new(candidate, first.Defaults, consent, final), first);
    }
}

/// <summary>
/// One-click setup from Settings: checks the service, requires administrator rights, loads the policy to enforce, validates
/// it, reviews the takeover and takes over when nothing needs the user. It stops at the first step that fails or needs the
/// user; a review that needs them waits in PendingReview for the takeover dialog.
/// </summary>
public sealed class Setup(Func<ServiceRequest, Task<ServiceResponse>> send)
{
    public const int Service = 0, Administrator = 1, Policy = 2, Validate = 3, Review = 4, TakeOver = 5;
    private readonly SetupStep[] steps = Fresh();

    public IReadOnlyList<SetupStep> Steps => steps;
    public bool Running { get; private set; }
    public TakeoverReview? PendingReview { get; private set; }
    /// <summary>Raised whenever a step changes.</summary>
    public event Action? Changed;

    private static SetupStep[] Fresh() =>
        [new("Check the service"), new("Administrator rights"), new("Load the policy"), new("Validate"), new("Review the takeover"), new("Take over")];

    /// <param name="draft">The editor's policy.</param>
    /// <param name="adopt">Replaces the draft's enforcement fields with a service policy, saves it and returns the draft to use from then on.</param>
    public async Task<SetupOutcome> RunAsync(AppState draft, bool elevated, Func<AppState, long?, AppState> adopt)
    {
        if (Running) throw new InvalidOperationException("Setup is already running.");
        Running = true; PendingReview = null; Fresh().CopyTo(steps, 0); Changed?.Invoke();
        try { return await RunSteps(draft, elevated, adopt); }
        finally { Running = false; Changed?.Invoke(); }
    }

    /// <summary>Records what the takeover dialog did with the pending review: the service's answer when it took over, else null.</summary>
    public void Reviewed(ServiceResponse? takeover)
    {
        PendingReview = null;
        if (takeover is { Success: true }) { Set(Review, SetupState.Done, "Reviewed."); Set(TakeOver, SetupState.Done, takeover.Message); }
        else Set(Review, SetupState.NeedsYou, "The review was closed without taking over. Set up again to review it.");
    }

    private async Task<SetupOutcome> RunSteps(AppState draft, bool elevated, Func<AppState, long?, AppState> adopt)
    {
        // The service answers, and Windows Firewall is in control: no takeover is active or waiting for recovery.
        Set(Service, SetupState.Running);
        var answer = await Ask(new("status"));
        if (!answer.Success || answer.Status is not { } status)
            return Stop(Service, SetupState.Failed, $"The service did not answer: {answer.Message} Start the Darkwire service, or reinstall Darkwire.");
        if (status.Active)
        {
            Set(Service, SetupState.Done, $"Darkwire already enforces {Modes.Name(status.Mode)}. Nothing to set up.");
            Set(Administrator, SetupState.Skipped);
            Set(Policy, SetupState.Running);
            var active = await Ask(new("policy"));
            if (!active.Success || active.Policy is null) return Stop(Policy, SetupState.Failed, "The active policy could not be loaded: " + active.Message);
            adopt(active.Policy, active.Status?.PolicyRevision);
            Set(Policy, SetupState.Done, "Loaded the active policy into the editor.");
            foreach (var step in new[] { Validate, Review, TakeOver }) Set(step, SetupState.Skipped);
            return SetupOutcome.AlreadyActive;
        }
        if (status.Phase != "Inactive") return Stop(Service, SetupState.Failed, "Darkwire needs recovery first: " + status.Message);
        Set(Service, SetupState.Done, "Connected. Windows Firewall is in control.");

        // Validating and taking over go through the service's administrator pipe; stopping before the policy step leaves the draft as it was.
        if (!elevated) return Stop(Administrator, SetupState.NeedsYou, "Darkwire is not running as administrator. Restart it as administrator, then set up again.");
        Set(Administrator, SetupState.Done, "Running as administrator.");

        // The service keeps the policy it last enforced after Windows Firewall is restored. It comes back only into a draft
        // with no rules of its own, so no edit is overwritten.
        Set(Policy, SetupState.Running);
        var stored = await Ask(new("policy"));
        if (!stored.Success || stored.Policy is null) return Stop(Policy, SetupState.Failed, "The service policy could not be loaded: " + stored.Message);
        var own = Own(draft); var earlier = Own(stored.Policy);
        if (own == 0 && earlier > 0)
        {
            draft = adopt(stored.Policy, stored.Status?.PolicyRevision);
            Set(Policy, SetupState.Done, $"Restored the policy Darkwire enforced before: {Modes.Name(draft.Mode)}, {Rules(earlier)} of your own.");
        }
        else Set(Policy, SetupState.Done, own == 0
            ? $"{Modes.Name(draft.Mode)}, inheriting Windows Firewall's rules."
            : $"Your draft: {Modes.Name(draft.Mode)}, {Rules(own)} of your own, inheriting Windows Firewall's rules.");

        Set(Validate, SetupState.Running);
        var (review, first) = await TakeoverReview.PrepareAsync(draft, Ask);
        if (review is null) return Stop(Validate, SetupState.Failed, Problem(first));
        if (!review.Final.Success) return Stop(Validate, SetupState.Failed, Problem(review.Final));
        var outOfScope = review.OutOfScope.Count;
        Set(Validate, SetupState.Done, $"The policy can be installed: {review.Imported.Count:N0} Windows rules inherited" +
            (outOfScope > 0 ? $", {outOfScope:N0} of them left out or reduced, never widened." : "."));

        Set(Review, SetupState.Running);
        if (review.NeedsUser)
        {
            PendingReview = review;
            var reasons = new List<string>();
            if (review.Consent.Count > 0) reasons.Add($"{Count(review.Consent.Count, "broader block needs", "broader blocks need")} your consent.");
            if (review.Added.Count > 0) reasons.Add($"{Count(review.Added.Count, "enabled rule doesn't", "enabled rules don't")} come from Windows.");
            return Stop(Review, SetupState.NeedsYou, string.Join(" ", reasons) + " Look them over to take over.", SetupOutcome.NeedsReview);
        }
        Set(Review, SetupState.Done, "Nothing needs your consent, and every enabled rule comes from Windows.");

        Set(TakeOver, SetupState.Running);
        var result = await Ask(new("takeover", review.Candidate));
        if (!result.Success) return Stop(TakeOver, SetupState.Failed, Problem(result));
        if (result.Policy is not null) adopt(result.Policy, result.Status?.PolicyRevision);
        Set(TakeOver, SetupState.Done, result.Message);
        return SetupOutcome.TookOver;
    }

    /// <summary>A failed request is an answer too: setup reports it at its step instead of throwing.</summary>
    private async Task<ServiceResponse> Ask(ServiceRequest request)
    {
        try { return await send(request); }
        catch (Exception error) when (error is not OutOfMemoryException) { return new(false, error.Message); }
    }

    // Rules the service keeps as the user's own when it merges Windows' rules in.
    private static int Own(AppState policy) => policy.Rules.Count(r => r.WindowsRuleId is null && r.Source != "Windows Firewall");

    private static string Rules(int count) => Count(count, "rule", "rules");
    private static string Count(int count, string one, string many) => $"{count:N0} {(count == 1 ? one : many)}";

    private static string Problem(ServiceResponse response)
    {
        var errors = response.Errors ?? [];
        return string.Join(" ", new[] { response.Message }.Concat(errors.Take(3))) + (errors.Count > 3 ? $" ({errors.Count - 3:N0} more.)" : "");
    }

    private SetupOutcome Stop(int step, SetupState state, string detail, SetupOutcome outcome = SetupOutcome.Stopped)
    {
        Set(step, state, detail); return outcome;
    }

    private void Set(int step, SetupState state, string detail = "")
    {
        steps[step] = steps[step] with { State = state, Detail = detail }; Changed?.Invoke();
    }
}
