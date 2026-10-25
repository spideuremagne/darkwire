using Darkwire.Host;

internal static class ApplicationIconChecks
{
    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool value, string reason = "Assertion failed") { if (!value) throw new Exception(reason); }
        check("Application icons accept only unambiguous absolute executable paths", () =>
        {
            Expect(ApplicationIcons.NormalizePath(@"C:\Apps\browser.exe") == @"C:\Apps\browser.exe");
            Expect(ApplicationIcons.NormalizePath("\"C:/Program Files/Browser/browser.EXE\"") == @"C:\Program Files\Browser\browser.EXE");
            foreach (var path in new[] { "", "*", "System", "browser.exe", @"C:browser.exe", @"\Apps\browser.exe", @"\\server\share\browser.exe",
                @"\\?\C:\Apps\browser.exe", @"\\.\pipe\browser.exe", "https://host/browser.exe", @"C:\Apps\browser.lnk", @"C:\Apps\browser.exe:stream.exe",
                @"C:\Apps\*.exe", @"C:\Apps.\browser.exe", @"C:\Apps \browser.exe", @"C:\Apps\browser.exe --switch" })
                Expect(ApplicationIcons.NormalizePath(path) is null, "Icon path should be rejected: " + path);
        });
        check("Application icon cache deduplicates paths and bounds pending reads", () =>
        {
            var release = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var calls = 0;
            var cache = new ApplicationIconCache<int>(2, 1, async _ => { Interlocked.Increment(ref calls); started.TrySetResult(true); return await release.Task; }, () => Task.FromResult(-1));
            var first = cache.GetAsync(@"C:\A.exe");
            Expect(ReferenceEquals(first, cache.GetAsync(@"c:\a.EXE")), "Case-insensitive copies must share one task.");
            var second = cache.GetAsync(@"C:\B.exe");
            Expect(started.Task.Wait(TimeSpan.FromSeconds(2)) && calls == 1, "Only one reader may run.");
            Expect(cache.GetAsync(@"C:\C.exe").GetAwaiter().GetResult() == -1 && cache.Count == 2, "Saturation must not queue extra work.");
            release.SetResult(7); Expect(Task.WhenAll(first, second).Wait(TimeSpan.FromSeconds(2)) && calls == 2);
            Expect(cache.GetAsync(@"C:\C.exe").GetAwaiter().GetResult() == 7 && cache.Count == 2, "Completed entries can be replaced.");
        });
        check("Application icon cache evicts least recently used completed icons and keeps failure fallback", () =>
        {
            var reads = new Dictionary<string, int>();
            var cache = new ApplicationIconCache<int>(2, 2, key =>
            {
                reads[key] = reads.GetValueOrDefault(key) + 1;
                return key == "missing" ? Task.FromException<int>(new IOException("No executable")) : Task.FromResult(reads[key]);
            }, () => Task.FromResult(-1));
            Expect(cache.GetAsync("a").Result == 1 && cache.GetAsync("b").Result == 1 && cache.GetAsync("a").Result == 1);
            Expect(cache.GetAsync("c").Result == 1 && cache.GetAsync("a").Result == 1 && cache.GetAsync("b").Result == 2);
            Expect(cache.GetAsync("missing").Result == -1 && cache.GetAsync("missing").Result == -1 && reads["missing"] == 1);
            Expect(cache.Count == 2);
        });
    }
}
