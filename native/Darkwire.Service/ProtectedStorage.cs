using System.Security.AccessControl;
using System.Security.Principal;

namespace Darkwire.Service;

internal static class ProtectedStorage
{
    private static readonly string[] TrustedOwners = ["S-1-5-18", "S-1-5-32-544"];
    public static void Verify()
    {
        var programRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Darkwire");
        var programService = Path.Combine(programRoot, "Service");
        if (!Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\').Equals(programService, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("The service must run from its protected installation directory.");
        var stateRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Darkwire");
        foreach (var directory in new[] { programRoot, programService, stateRoot, ServiceHost.StateDirectory })
        {
            if (!Directory.Exists(directory)) throw new UnauthorizedAccessException("A protected service directory is missing. Reinstall the service.");
            CheckParents(directory); VerifyAcl(new DirectoryInfo(directory).GetAccessControl());
        }
        VerifyTree(programService);
        VerifyTree(ServiceHost.StateDirectory);
        InstallationIntegrity.Verify(programService);
    }
    internal static void VerifyTree(string directory)
    {
        // Inspect before descending so a junction cannot redirect verification outside this tree. The service's own
        // temporary download files can vanish between listing and inspection; an entry that is gone has nothing to check.
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
        {
            try
            {
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Protected state contains a reparse point.");
                if ((attributes & FileAttributes.Directory) != 0)
                { VerifyAcl(new DirectoryInfo(entry).GetAccessControl()); VerifyTree(entry); }
                else VerifyAcl(new FileInfo(entry).GetAccessControl());
            }
            catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException) { }
        }
    }
    internal static void CheckParents(string directory)
    {
        for (DirectoryInfo? item = new(directory); item is not null; item = item.Parent)
            if ((item.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("The service directory traverses a reparse point.");
    }
    internal static void VerifyAcl(FileSystemSecurity security)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier))?.Value;
        if (owner is null || !TrustedOwners.Contains(owner)) throw new UnauthorizedAccessException("Service state must be owned by SYSTEM or Administrators.");
        const FileSystemRights writes = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & writes) != 0 && !TrustedOwners.Contains(rule.IdentityReference.Value))
                throw new UnauthorizedAccessException("Service files or state are writable by an untrusted identity.");
    }
}
