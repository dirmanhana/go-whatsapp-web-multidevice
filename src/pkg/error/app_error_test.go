package error

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServiceUnavailableErrorsAreNotAuth(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"ErrNotConnected", ErrNotConnected},
		{"ErrNotLoggedIn", ErrNotLoggedIn},
		{"ErrReconnect", ErrReconnect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generic, ok := tc.err.(GenericError)
			assert.True(t, ok, "must implement GenericError")
			// These describe the WhatsApp service state, not the caller's
			// credentials. Returning 401 here would log the browser dashboard
			// out on a temporarily disconnected device.
			assert.Equal(t, http.StatusServiceUnavailable, generic.StatusCode())
			assert.Equal(t, "SERVICE_UNAVAILABLE", generic.ErrCode())
		})
	}
}