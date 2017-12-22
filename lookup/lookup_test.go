package lookup

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLookup(t *testing.T) {
	tests := []struct {
		name  string
		email string
		err   bool
	}{
		{
			name:  "existing key lookup",
			email: "sigdown.test@antontsv.github.io",
			err:   false,
		},
		{
			name:  "unknown key lookup",
			email: "something@non-existing.com",
			err:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			res, err := Lookup(ctx, tc.email)
			if err == nil && tc.err {
				t.Errorf("expected to get key lookup error for %s", tc.email)
			}
			if !tc.err && !strings.Contains(res, "PUBLIC KEY BLOCK") {
				t.Errorf("no key was returned for %s", tc.email)
			}
		})
	}
}
