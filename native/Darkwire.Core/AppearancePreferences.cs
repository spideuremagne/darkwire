namespace Darkwire.Core;

/// <summary>Local presentation preferences. None changes network policy or enforcement.</summary>
public static class AppearancePreferences
{
    public static void Normalize(AppState state)
    {
        state.AppAppearance = Canonical(state.AppAppearance, ["System", "Dark", "Light"], "System");
        state.NavigationPlacement = Canonical(state.NavigationPlacement, ["Left", "Top"], "Left");
        state.AtlasPresentation = Canonical(state.AtlasPresentation, ["Standard", "Observatory"], "Standard");
        state.MapEffectPreset = Canonical(state.MapEffectPreset, ["Focus", "Balanced", "Cinematic", "Custom"], "Balanced");
        state.EffectIntensity = Math.Clamp(state.EffectIntensity, 0, 100);
    }

    public static bool IsLight(string? choice, bool windowsUsesLight) => choice switch
    {
        "Light" => true, "Dark" => false, _ => windowsUsesLight
    };

    public static void ApplyEffectPreset(AppState state, string preset)
    {
        if (preset is not ("Focus" or "Balanced" or "Cinematic")) return;
        state.MapEffectPreset = preset;
        state.RouteParticles = state.EndpointRipples = state.PolicyShockwaves = state.AtmosphereGlow = preset != "Focus";
        state.AmbientParticles = state.AutoRotateGlobe = preset == "Cinematic";
        state.EffectIntensity = preset switch { "Focus" => 20, "Cinematic" => 80, _ => 45 };
        // A visual preset never overrides the user's reduced-motion preference.
    }

    private static string Canonical(string? value, string[] choices, string fallback) =>
        choices.FirstOrDefault(c => c.Equals(value, StringComparison.OrdinalIgnoreCase)) ?? fallback;
}
