//go:build windows

package identity

import "golang.org/x/sys/windows"

// SecureFile locks down a secret-holding file (the key file, edit's transient
// plaintext) so only the current user can read it.
//
// On Windows the Unix permission bits passed to os.WriteFile are ignored, so a
// plain 0600 does NOT keep other local users out. We instead set an explicit
// DACL granting full control to the current user's SID only, and mark it
// PROTECTED so inherited ACEs from the parent directory are stripped.
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
