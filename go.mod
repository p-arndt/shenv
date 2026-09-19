module shenv

go 1.26

// Pinned to a patched 1.26.x: the stdlib is compiled into the shipped binaries,
// so the toolchain that builds a release — not just the `go` directive — decides
// which advisories users carry. CI reads this line via go-version-file.
toolchain go1.26.8

require (
	filippo.io/age v1.3.1
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	golang.org/x/crypto v0.54.0 // indirect
)
