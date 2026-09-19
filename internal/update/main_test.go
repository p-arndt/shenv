package update

import (
	"os"
	"testing"
)

// The tests serve release assets from local httptest servers over plain http.
func TestMain(m *testing.M) {
	allowLoopbackHTTP = true
	os.Exit(m.Run())
}
