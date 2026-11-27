using System.Security.AccessControl;
using System.Security.Principal;

namespace ClaudeGuard.Core;

/// <summary>Creates directories readable only by SYSTEM and Administrators (no inherited Users:RX),
/// regardless of the parent ACL or a custom path in config.json.</summary>
public static class SecureDir
{
    public static void Ensure(string path)
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        }

        var di = new DirectoryInfo(path);
        if (!di.Exists) di.Create(sec);
        else di.SetAccessControl(sec);
    }
}
