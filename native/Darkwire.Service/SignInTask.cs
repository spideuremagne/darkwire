using System.Runtime.InteropServices;
using System.Security;

namespace Darkwire.Service;

/// <summary>
/// The scheduled task that opens the desktop app in the tray whenever someone signs in. The app needs administrator rights,
/// and Windows never starts a Run key entry that needs them at sign-in; a logon task with the highest privileges starts it
/// elevated, with no prompt, for administrators. A standard user's token cannot start it, as it cannot start the app by
/// hand without an administrator's credentials. Each user's app exits at once if that user turned sign-in start off.
/// </summary>
internal static class SignInTask
{
    public const string Name = "Darkwire";

    /// <summary>
    /// For every member of Users at their own sign-in, in their session, without stopping it after the default three days,
    /// with one instance per signed-in user, at normal priority (tasks default to below normal), on battery too.
    /// </summary>
    public static string Definition(string application) => $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo><Author>Darkwire</Author><Description>Opens Darkwire in the tray when you sign in. Turn it off in Darkwire, Settings, Startup.</Description></RegistrationInfo>
          <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
          <Principals><Principal id="Users"><GroupId>S-1-5-32-545</GroupId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
          <Settings>
            <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
            <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
            <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
            <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
            <Priority>5</Priority>
          </Settings>
          <Actions Context="Users"><Exec><Command>"{SecurityElement.Escape(application)}"</Command><Arguments>--tray</Arguments></Exec></Actions>
        </Task>
        """;

    /// <summary>Creates the task, or replaces an earlier version's.</summary>
    public static void Register(string application) => Folder(folder =>
    {
        const int CreateOrUpdate = 6, GroupLogon = 4;
        folder.RegisterTask(Name, Definition(application), CreateOrUpdate, null, null, GroupLogon, null);
    });

    public static void Remove() => Folder(folder =>
    {
        try { folder.DeleteTask(Name, 0); }
        catch (COMException error) when (error.HResult == unchecked((int)0x80070002)) { }
    });

    private static void Folder(Action<dynamic> act)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!;
        dynamic scheduler = Activator.CreateInstance(type)!;
        try
        {
            scheduler.Connect();
            act(scheduler.GetFolder("\\"));
        }
        finally { Marshal.FinalReleaseComObject(scheduler); }
    }
}
