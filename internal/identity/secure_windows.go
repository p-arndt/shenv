//go:build windows

package identity

import (
	"os"

	"golang.org/x/sys/windows"
)

// SecureFile locks down a secret-holding file (the key file, edit's transient
// plaintext) so only the current user can read it.
//
// On Windows the Unix permission bits passed to os.WriteFile are ignored, so a
// plain 0600 does NOT keep other local users out. We instead set an explicit
// DACL granting full control to the current user's SID only, and mark it
// PROTECTED so inherited ACEs from the parent directory are stripped.
// checkKeyPermissions has nothing to compare on Windows: the Unix mode bits the
// file reports are synthesised and say nothing about who may read it — the DACL
// does. So instead of refusing the key, re-assert the owner-only DACL, which a
// hand-copied or restored key file will not carry. Best effort: a key we cannot
// re-secure (another owner, a network share) is still usable, and failing here
// would lock the user out of their own secrets.
func checkKeyPermissions(path string, _ os.FileInfo) error {
	_ = SecureFile(path)
	return nil
}

func SecureFile(path string) error {
	token := windows.GetCurrentProcessToken()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sid := tokenUser.User.Sid

	access := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}

	dacl, err := windows.ACLFromEntries(access, nil)
	if err != nil {
		return err
	}

	// PROTECTED_DACL_SECURITY_INFORMATION replaces (not merges) the inherited
	// DACL — the equivalent of `icacls <file> /inheritance:r`.
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}
