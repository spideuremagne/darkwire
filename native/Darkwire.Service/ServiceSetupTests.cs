using System.Security.AccessControl;

namespace Darkwire.Service;

internal static class ServiceSetupTests
{
    public static void Run(Action<string, Action> check)
    {
        static void Assert(bool value, string reason = "Setup invariant failed.") { if (!value) throw new Exception(reason); }
        check("Setup actions distinguish removal from an upgrade", () =>
        {
            Assert(ServiceSetup.Parse(["--install"]) == ("install", false) && ServiceSetup.Parse(["--rollback"]) == ("rollback", false));
            Assert(ServiceSetup.Parse(["--uninstall"]) == ("uninstall", false));
            Assert(ServiceSetup.Parse(["--uninstall", "{5B1B6E3C-7A61-4F3E-9C1D-2B8E4D5A6F70}"]) == ("uninstall", true));
            Assert(ServiceSetup.Parse(["--uninstall", "later"]) is null && ServiceSetup.Parse(["--install", "--rollback"]) is null && ServiceSetup.Parse([]) is null);
        });
        check("Setup ACLs pass the service's own storage checks", () =>
        {
            foreach (var sddl in new[] { ServiceSetup.ProgramDirectorySddl, ServiceSetup.StateSddl })
            {
                var directory = new DirectorySecurity(); directory.SetSecurityDescriptorSddlForm(sddl);
                ProtectedStorage.VerifyAcl(directory); Assert(directory.AreAccessRulesProtected);
            }
            var file = new FileSecurity(); file.SetSecurityDescriptorSddlForm(ServiceSetup.ProgramFileSddl);
            ProtectedStorage.VerifyAcl(file); Assert(file.AreAccessRulesProtected);
            // ProgramData's inherited ACL lets Users create entries; state like that must be refused.
            var shared = new DirectorySecurity(); shared.SetSecurityDescriptorSddlForm("O:BAG:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;CI;0x116;;;BU)");
            try { ProtectedStorage.VerifyAcl(shared); throw new Exception("User-writable state accepted"); } catch (UnauthorizedAccessException) { }
        });
        check("The sign-in task opens the app in the tray, elevated, for every user at their own sign-in, and never times out", () =>
        {
            const string app = @"C:\Program Files\Darkwire\Darkwire.exe";
            var xml = System.Xml.Linq.XDocument.Parse(SignInTask.Definition(app));
            System.Xml.Linq.XNamespace task = "http://schemas.microsoft.com/windows/2004/02/mit/task";
            string? Value(params string[] path) => path.Aggregate((System.Xml.Linq.XElement?)xml.Root, (e, name) => e?.Element(task + name))?.Value;
            Assert(xml.Root!.Element(task + "Triggers")!.Elements().Single().Name == task + "LogonTrigger" && Value("Triggers", "LogonTrigger", "UserId") is null, "The trigger is not every user's sign-in.");
            Assert(Value("Principals", "Principal", "GroupId") == "S-1-5-32-545" && Value("Principals", "Principal", "RunLevel") == "HighestAvailable");
            Assert(Value("Settings", "ExecutionTimeLimit") == "PT0S" && Value("Settings", "MultipleInstancesPolicy") == "Parallel" && Value("Settings", "DisallowStartIfOnBatteries") == "false");
            Assert(Value("Actions", "Exec", "Command") == $"\"{app}\"" && Value("Actions", "Exec", "Arguments") == "--tray");
            // A path is data in the definition, never markup.
            Assert(System.Xml.Linq.XDocument.Parse(SignInTask.Definition(@"C:\A&B <x>\Darkwire.exe")).Descendants(task + "Command").Single().Value == "\"C:\\A&B <x>\\Darkwire.exe\"");
        });
        check("Service registration matches the identity clients verify", () =>
        {
            var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Darkwire", "Service", "Darkwire.Service.exe");
            Assert(ServiceRegistration.BinaryPath == $"\"{expected}\" --service");
            Assert(ServiceRegistration.ProcessEnvironment.Contains("DOTNET_EnableDiagnostics=0") && ServiceRegistration.ProcessEnvironment.Contains("DOTNET_STARTUP_HOOKS="));
            var descriptor = new RawSecurityDescriptor(ServiceRegistration.Sddl);
            Assert(descriptor.DiscretionaryAcl!.Count == 3 && (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0);
        });
    }
}
