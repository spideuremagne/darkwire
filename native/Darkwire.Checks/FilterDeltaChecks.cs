using Darkwire.Core;
using Darkwire.Engine;

/// <summary>Filters keep their keys from one apply to the next, so an apply changes only the filters that differ.</summary>
internal static class FilterDeltaChecks
{
    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool value, string reason = "Filter delta invariant failed.") { if (!value) throw new Exception(reason); }
        static WfpRegistration Registration(string name, ulong weight = 100, string network = "203.0.113.0/24", uint flags = 1, bool locked = false) =>
            new(new NativeFilter(name, null, false, TrafficDirection.Outbound, RuleAction.Deny, weight, RemoteNetwork: network), WfpInstallationPlan.AuthorizationLayer(false, TrafficDirection.Outbound), flags, locked);
        // The secret a service drew as it started.
        var secret = new byte[32]; Array.Fill(secret, (byte)7);
        Guid[] Keys(params WfpRegistration[] registrations) => FilterDelta.Keys([.. registrations.Select(r => (r, WfpConditions.Resolve(r.Filter)))], secret);
        (Guid Key, bool BootTime, bool Lock)[] Wanted(WfpRegistration[] registrations) => [.. Keys(registrations).Select((key, i) => (key, registrations[i].BootTime, registrations[i].Lock))];
        (ulong Id, Guid Key, bool BootTime, bool Disabled, bool Lock)[] Installed(WfpRegistration[] registrations) =>
            [.. Keys(registrations).Select((key, i) => ((ulong)(i + 1), key, registrations[i].BootTime, false, registrations[i].Lock))];
        // Filters this service installed itself.
        static bool Trusted(ulong _) => true;

        check("Filter keys: the same content gets the same key every time, and anything WFP holds of it changes the key", () =>
        {
            var plain = Registration("FireHOL Level 1");
            Expect(Keys(plain)[0] == Keys(Registration("FireHOL Level 1"))[0], "The same filter got another key.");
            WfpRegistration[] changed = [Registration("FireHOL Level 2"), Registration("FireHOL Level 1", weight: 101), Registration("FireHOL Level 1", network: "203.0.114.0/24"),
                Registration("FireHOL Level 1", flags: 2), Registration("FireHOL Level 1", locked: true), plain with { Filter = plain.Filter with { Action = RuleAction.Allow } },
                plain with { Filter = plain.Filter with { RuleId = Guid.NewGuid() } }, plain with { Layer = WfpInstallationPlan.AuthorizationLayer(false, TrafficDirection.Inbound) }];
            Expect(changed.Select(r => Keys(r)[0]).Append(Keys(plain)[0]).Distinct().Count() == changed.Length + 1, "A change kept the key.");
            // Filters alike in everything are told apart by their order, and keep their keys while nothing else changes.
            var twice = Keys(plain, plain, Registration("Other"));
            Expect(twice.Distinct().Count() == 3 && twice[0] == Keys(plain)[0] && twice.SequenceEqual(Keys(plain, plain, Registration("Other"))));
            // The service's next start draws another secret: every key changes, so its first install reuses none.
            var other = new byte[32]; Array.Fill(other, (byte)8);
            WfpRegistration[] same = [plain, plain, Registration("Other")];
            Expect(!FilterDelta.Keys([.. same.Select(r => (r, WfpConditions.Resolve(r.Filter)))], other).Intersect(twice).Any(), "Another secret gave a key again.");
        });
        check("Filter delta: what is installed as wanted stays, and only what differs is deleted and added", () =>
        {
            WfpRegistration[] before = [Registration("A"), Registration("B"), Registration("C"), Registration("Startup protection", flags: 2), Registration("Lock", locked: true)];
            var installed = Installed(before);
            var (delete, add, kept) = FilterDelta.Between(installed, Wanted(before), Trusted);
            Expect(delete.Count == 0 && add.Count == 0 && kept.Count == 5 && kept.All(k => k.Value == (ulong)(k.Key + 1)), "An unchanged plan changed filters.");
            // A VPN profile connecting changes one filter here: B goes, its replacement comes, the rest stay with their IDs.
            WfpRegistration[] after = [before[0], Registration("B", network: "198.51.100.7/32"), before[2], before[3], before[4], Registration("D")];
            (delete, add, kept) = FilterDelta.Between(installed, Wanted(after), Trusted);
            Expect(delete.SequenceEqual([2UL]) && add.SequenceEqual([1, 5]) && kept.Count == 4 && kept[0] == 1 && kept[2] == 3 && kept[3] == 4 && kept[4] == 5);
            // An empty plan, as Open mode or restoring Windows Firewall, removes everything.
            (delete, add, kept) = FilterDelta.Between(installed, [], Trusted);
            Expect(delete.Count == 5 && add.Count == 0 && kept.Count == 0);
            // Before the service has installed anything since it started, none is trusted, and everything is replaced.
            (delete, add, kept) = FilterDelta.Between(installed, Wanted(before), _ => false);
            Expect(delete.Count == 5 && add.Count == 5 && kept.Count == 0, "Filters the service had not installed were kept.");
        });
        check("Filter delta: filters under other keys, as earlier versions installed, disabled ones and doubles are replaced", () =>
        {
            WfpRegistration[] plan = [Registration("A"), Registration("B")];
            var earlier = plan.Select((r, i) => ((ulong)(i + 1), Guid.NewGuid(), false, false, false));
            var (delete, add, kept) = FilterDelta.Between(earlier, Wanted(plan), Trusted);
            Expect(delete.Count == 2 && add.SequenceEqual([0, 1]) && kept.Count == 0, "Filters under random keys were kept.");
            var installed = Installed(plan);
            installed[0] = installed[0] with { Disabled = true };
            // The same key installed twice is impossible in WFP, yet only one could stand for the wanted filter.
            (delete, add, kept) = FilterDelta.Between([.. installed, (9UL, installed[1].Key, false, false, false)], Wanted(plan), Trusted);
            Expect(delete.SequenceEqual([1UL, 9UL]) && add.SequenceEqual([0]) && kept.Single().Value == 2);
            // A filter of another kind under a wanted key, boot-time or startup lock, is replaced as well.
            (delete, add, _) = FilterDelta.Between([installed[1] with { BootTime = true }], Wanted(plan), Trusted);
            Expect(delete.SequenceEqual([2UL]) && add.SequenceEqual([0, 1]));
            // Anyone can derive a key: a filter put back under one by someone else, with an ID the service never installed, is replaced.
            (delete, add, kept) = FilterDelta.Between(Installed(plan), Wanted(plan), id => id != 2);
            Expect(delete.SequenceEqual([2UL]) && add.SequenceEqual([1]) && kept.Single().Value == 1);
        });
    }
}
