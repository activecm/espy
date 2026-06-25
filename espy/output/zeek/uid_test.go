package zeek

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// Zeek UIDs are the letter "C" followed by one or more base62 characters.
var uidPattern = regexp.MustCompile(`^C[0-9a-zA-Z]+$`)

func TestNewUIDFormat(t *testing.T) {
	uid := NewUID()
	require.Regexp(t, uidPattern, uid, "UID should be 'C' followed by base62 characters")
}

func TestNewUIDUniqueness(t *testing.T) {
	const iterations = 10000
	seen := make(map[string]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		uid := NewUID()
		_, dup := seen[uid]
		require.False(t, dup, "NewUID produced a duplicate value: %s", uid)
		seen[uid] = struct{}{}
	}
}
