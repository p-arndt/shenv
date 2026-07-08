//go:build windows

package harden

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WerAddExcludedApplication lives in wer.dll but is not exported by
// golang.org/x/sys/windows, so it is bound here at runtime. Adding a
// third-party wrapper just for one call is not worth it, and a missing DLL or
// symbol simply makes the call a no-op — which is exactly the best-effort
// behavior we want.
var (
	modwer                        = windows.NewLazySystemDLL("wer.dll")
	procWerAddExcludedApplication = modwer.NewProc("WerAddExcludedApplication")
)

// Process asks Windows Error Reporting not to capture crash dumps for this
// executable.
func Process() {
	// Excluding our own executable keeps WER from writing a .dmp — which would
	// contain the decrypted key and .env plaintext — under the user profile on a
	// crash. Passing bAllUsers=FALSE scopes the exclusion to the current user, so
	// no admin rights are needed. Honest caveats: this excludes by executable
	// path only, so it does nothing against an admin-configured LocalDumps
	// registry policy (WER consults that regardless), and nothing against a live
	// debugger already attached to the process.
	exe, err := os.Executable()
	if err != nil {
		return
	}
	name, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return
	}
	// LazyProc.Call panics — it does not error — when the DLL or symbol is
	// missing (Wine, stripped-down Windows editions); Find is what actually
	// makes the degradation to a no-op.
	if procWerAddExcludedApplication.Find() != nil {
		return
	}
	_, _, _ = procWerAddExcludedApplication.Call(uintptr(unsafe.Pointer(name)), 0)
}
