using Darkwire.Core;
using Darkwire.Host;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class AppearanceChecks
{
    public static void Run(Action<string, Action> check)
    {
        static void Expect(bool value, string reason = "Assertion failed") { if (!value) throw new Exception(reason); }
        static string Json(AppState state) => JsonSerializer.Serialize(state, StateStore.JsonOptions);

        check("Earlier settings gain appearance defaults without replacing map and motion choices", () =>
        {
            var legacy = StateStore.Upgrade(JsonSerializer.Deserialize<AppState>(
                """{"SchemaVersion":1,"Theme":"Verdant","MapProjection":"Globe","MapProjectionChosen":true,"ReducedMotion":true,"BackgroundPreset":"Clouds"}""")!);
            AppearancePreferences.Normalize(legacy);
            Expect(legacy.AppAppearance == "System" && legacy.NavigationPlacement == "Left" && legacy.AtlasPresentation == "Standard");
            Expect(legacy.MapEffectPreset == "Balanced" && legacy.EffectIntensity == 45);
            Expect(legacy.RouteParticles && legacy.EndpointRipples && legacy.PolicyShockwaves && legacy.AtmosphereGlow);
            Expect(!legacy.AmbientParticles && !legacy.AutoRotateGlobe);
            Expect(legacy.Theme == "Verdant" && legacy.MapProjection == "Globe" && legacy.ReducedMotion && legacy.BackgroundPreset == "Clouds");
        });

        check("Appearance, independent layout and individual effects survive saved-settings round trip", () =>
        {
            var file = Path.Combine(Path.GetTempPath(), "darkwire-appearance-" + Guid.NewGuid().ToString("N") + ".json");
            var state = new AppState
            {
                AppAppearance = "Light", NavigationPlacement = "Top", AtlasPresentation = "Observatory", MapEffectPreset = "Custom",
                RouteParticles = false, EndpointRipples = true, PolicyShockwaves = false, AmbientParticles = true,
                AtmosphereGlow = false, AutoRotateGlobe = true, EffectIntensity = 67, ReducedMotion = true,
                Theme = "Classic", MapProjection = "Globe", MapProjectionChosen = true
            };
            try
            {
                StateStore.Write(file, state);
                var restored = StateStore.Read(file); AppearancePreferences.Normalize(restored);
                Expect(Json(restored) == Json(state), "A saved visual preference changed or disappeared.");
            }
            finally { File.Delete(file); }
        });

        check("Appearance normalization repairs invalid persisted values and is stable on repeated application", () =>
        {
            var state = new AppState
            {
                AppAppearance = "lIgHt", NavigationPlacement = "tOp", AtlasPresentation = "oBsErVaToRy", MapEffectPreset = "cUsToM",
                EffectIntensity = -50, RouteParticles = false, EndpointRipples = false, AmbientParticles = true
            };
            AppearancePreferences.Normalize(state);
            Expect(state.AppAppearance == "Light" && state.NavigationPlacement == "Top" && state.AtlasPresentation == "Observatory" && state.MapEffectPreset == "Custom");
            Expect(state.EffectIntensity == 0 && !state.RouteParticles && !state.EndpointRipples && state.AmbientParticles, "Normalization replaced individual effect choices.");
            var once = Json(state); AppearancePreferences.Normalize(state); Expect(Json(state) == once);
            state.AppAppearance = null!; state.NavigationPlacement = "sideways"; state.AtlasPresentation = ""; state.MapEffectPreset = "obsolete"; state.EffectIntensity = int.MaxValue;
            AppearancePreferences.Normalize(state);
            Expect(state.AppAppearance == "System" && state.NavigationPlacement == "Left" && state.AtlasPresentation == "Standard" && state.MapEffectPreset == "Balanced" && state.EffectIntensity == 100);
        });

        check("Page colors keep their roles: grey lavender text is muted, saturated violet an accent, warm peach a warning", () =>
        {
            foreach (var muted in new[] { "#A99DBA", "#B8AAC8", "#B4A9C4", "#BDB1CB", "#B7ADC8", "#8E859F" })
                Expect(AppearanceTheme.Role(muted) == "Muted", muted + " is secondary text, not an accent.");
            foreach (var accent in new[] { "#B7A0FF", "#C4B1E7", "#CCB7F2", "#E3B3FF", "#C4A9FF" })
                Expect(AppearanceTheme.Role(accent) == "Accent", accent + " is an accent.");
            Expect(AppearanceTheme.Role("#E8C9A8") == "Warning" && AppearanceTheme.Role("#E8B07A") == "Warning", "Warning details lost their color.");
            Expect(AppearanceTheme.Role("#F2849C") == "Red" && AppearanceTheme.Role("#7CE3BA") == "Green" && AppearanceTheme.Role("#ECE4F7") == "Text");
        });

        check("Explicit app palettes override Windows while System follows both Windows appearance states", () =>
        {
            foreach (var windowsLight in new[] { false, true })
            {
                Expect(AppearancePreferences.IsLight("System", windowsLight) == windowsLight);
                Expect(AppearancePreferences.IsLight(null, windowsLight) == windowsLight);
                Expect(AppearancePreferences.IsLight("unknown", windowsLight) == windowsLight);
                Expect(AppearancePreferences.IsLight("Light", windowsLight));
                Expect(!AppearancePreferences.IsLight("Dark", windowsLight));
            }
        });

        check("App appearance, navigation, atlas layout and map palette remain independent", () =>
        {
            foreach (var app in new[] { "System", "Dark", "Light" })
            foreach (var navigation in new[] { "Left", "Top" })
            foreach (var layout in new[] { "Standard", "Observatory" })
            foreach (var map in new[] { "Amethyst", "Glacier", "Verdant", "Classic" })
            {
                var state = new AppState { AppAppearance = app, NavigationPlacement = navigation, AtlasPresentation = layout, Theme = map, MapProjection = "Flat" };
                AppearancePreferences.Normalize(state); AppearancePreferences.ApplyEffectPreset(state, "Cinematic");
                Expect(state.AppAppearance == app && state.NavigationPlacement == navigation && state.AtlasPresentation == layout && state.Theme == map && state.MapProjection == "Flat",
                    $"A presentation choice changed another: {app}, {navigation}, {layout}, {map}.");
            }
        });

        check("Motion presets keep reduced motion authoritative and leave Custom choices intact", () =>
        {
            foreach (var reduced in new[] { false, true })
            foreach (var preset in new[] { "Focus", "Balanced", "Cinematic" })
            {
                var state = new AppState { ReducedMotion = reduced };
                AppearancePreferences.ApplyEffectPreset(state, preset);
                var moving = preset != "Focus"; var cinematic = preset == "Cinematic";
                Expect(state.MapEffectPreset == preset && state.ReducedMotion == reduced);
                Expect(state.RouteParticles == moving && state.EndpointRipples == moving && state.PolicyShockwaves == moving && state.AtmosphereGlow == moving);
                Expect(state.AmbientParticles == cinematic && state.AutoRotateGlobe == cinematic);
                Expect(state.EffectIntensity == (preset == "Focus" ? 20 : cinematic ? 80 : 45));
                var before = Json(state);
                foreach (var unsupported in new[] { "Custom", "unknown", "" }) { AppearancePreferences.ApplyEffectPreset(state, unsupported); Expect(Json(state) == before); }
            }
        });

        check("Appearance normalization and every motion preset leave network policy and existing preferences untouched", () =>
        {
            var profile = new VpnProfile { Name = "Private", Endpoint = "vpn.example.net:51820", Applications = [@"C:\Apps\browser.exe"], KillSwitch = true };
            var state = new AppState
            {
                Mode = FirewallMode.BlockNew, Rules = [new() { ApplicationName = "Browser", Path = @"C:\Apps\browser.exe", Action = RuleAction.Deny, RemotePorts = "443" }],
                VpnProfiles = [profile], DefaultOutboundVpnProfileId = profile.Id, OwnTraffic = OwnRoute.Profile, OwnTrafficProfileId = profile.Id,
                LocalNetworkBypassesVpn = false, InternalNetworks = InternalAccess.Block, RouteConnections = true, CoreNetworking = false, StartupLock = true,
                BlockedCountries = ["KP"], CountryAllowList = true, AllowedCountries = ["US", "CA"], BlockedAsns = [64496],
                Blocklists = [new() { Name = "Example", Url = "https://example.test/list", Entries = ["ads.example.test"] }], BlockedNames = ["ads.example.test"],
                DnsServers = [new() { Name = "Example DNS", Stamps = ["https://example.test/dns-query"], Listed = false }],
                ReducedMotion = true, CloseToTray = false, ReverseDnsEnabled = true, StartAtSignIn = false,
                MapOriginCountry = "CA", MapOriginCity = "Toronto", MapOriginLatitude = 43.65, MapOriginLongitude = -79.38, MapOriginAsked = true,
                Theme = "Verdant", MapProjection = "Globe", MapProjectionChosen = true, BackgroundPreset = "Clouds", CloudDirection = "Down",
                Columns = [new() { Name = "Application name", Width = 230, Order = 0 }], AppAppearance = "dark", NavigationPlacement = "top"
            };
            static string NonAppearance(AppState value)
            {
                var json = JsonNode.Parse(JsonSerializer.Serialize(value, StateStore.JsonOptions))!.AsObject();
                foreach (var field in new[] { "AppAppearance", "NavigationPlacement", "AtlasPresentation", "MapEffectPreset", "RouteParticles", "EndpointRipples", "PolicyShockwaves", "AmbientParticles", "AtmosphereGlow", "AutoRotateGlobe", "EffectIntensity" }) json.Remove(field);
                return json.ToJsonString();
            }
            var before = NonAppearance(state);
            AppearancePreferences.Normalize(state); Expect(NonAppearance(state) == before);
            foreach (var preset in new[] { "Focus", "Balanced", "Cinematic", "Custom" })
            { AppearancePreferences.ApplyEffectPreset(state, preset); Expect(NonAppearance(state) == before, preset + " changed state outside appearance."); }
            Expect(ReferenceEquals(state.VpnProfiles[0], profile), "Appearance work replaced policy objects.");
        });
    }
}
