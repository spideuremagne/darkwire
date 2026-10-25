using Darkwire.Host;

/// <summary>An upgrade's new build is noticed once it is in place and settled: never half written, nor while the installer runs.</summary>
internal static class InstalledBuildChecks
{
    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool value, string reason = "Installed build invariant failed.") { if (!value) throw new Exception(reason); }
        static void InFolder(Action<string> test)
        {
            var folder = Path.Combine(Path.GetTempPath(), "darkwire-build-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            try { test(folder); } finally { Directory.Delete(folder, true); }
        }
        static void Write(string folder, string name, string content, DateTime written)
        {
            var path = Path.Combine(folder, name); File.WriteAllText(path, content); File.SetLastWriteTimeUtc(path, written);
        }
        var built = new DateTime(2026, 10, 19, 22, 0, 0, DateTimeKind.Utc);
        void Build(string folder, DateTime written, string version)
        {
            Write(folder, "Darkwire.exe", "host", written); Write(folder, "Darkwire.dll", "app " + version, written); Write(folder, "Darkwire.Core.dll", "core " + version, written);
        }
        var settled = InstalledBuild.SettleFor;

        check("Installed build: the build this copy started with is no update", () => InFolder(folder =>
        {
            var now = built.AddDays(1); Build(folder, built, "a"); var installed = new InstalledBuild(folder, () => false, () => now);
            Expect(!installed.Check()); now += settled * 3; Expect(!installed.Check() && !installed.Replaced);
        }));
        check("Installed build: a new build counts once its programs stay unchanged long enough", () => InFolder(folder =>
        {
            var now = built.AddDays(1); Build(folder, built, "a"); var installed = new InstalledBuild(folder, () => false, () => now);
            Build(folder, built.AddHours(5), "b");
            Expect(!installed.Check(), "Noticed before it settled.");
            now += settled / 2; Expect(!installed.Check(), "Noticed before it settled.");
            now += settled / 2; Expect(installed.Check() && installed.Replaced && installed.Check());
        }));
        check("Installed build: a running installation or programs still changing keep it waiting", () => InFolder(folder =>
        {
            var now = built.AddDays(1); var installing = true; Build(folder, built, "a"); var installed = new InstalledBuild(folder, () => installing, () => now);
            Build(folder, built.AddHours(5), "b");
            Expect(!installed.Check()); now += settled * 2; Expect(!installed.Check(), "Noticed while Windows Installer ran.");
            installing = false; Expect(!installed.Check(), "The time under the installer counted.");
            now += settled / 2; Write(folder, "Darkwire.Core.dll", "core c", built.AddHours(6));
            Expect(!installed.Check()); now += settled / 2; Expect(!installed.Check(), "Noticed while its programs changed.");
            now += settled / 2; Expect(installed.Check());
        }));
        check("Installed build: other files, or Darkwire.exe gone, are no update", () => InFolder(folder =>
        {
            var now = built.AddDays(1); Build(folder, built, "a"); var installed = new InstalledBuild(folder, () => false, () => now);
            Write(folder, "setup.log", "written by setup", built.AddHours(5)); Write(folder, "WinRT.Runtime.dll", "other", built.AddHours(5));
            Expect(!installed.Check()); now += settled * 2; Expect(!installed.Check(), "Another program's file was taken for an update.");
            File.Delete(Path.Combine(folder, "Darkwire.exe")); Write(folder, "Darkwire.dll", "app b", built.AddHours(5));
            Expect(!installed.Check()); now += settled * 2; Expect(!installed.Check(), "A removed app would restart.");
        }));
        check("Installed build: a folder unread at start never reads as updated", () => InFolder(folder =>
        {
            var now = built.AddDays(1); var missing = Path.Combine(folder, "app"); var installed = new InstalledBuild(missing, () => false, () => now);
            Directory.CreateDirectory(missing); Build(missing, built, "a");
            Expect(!installed.Check()); now += settled * 2; Expect(!installed.Check());
        }));
    }
}
