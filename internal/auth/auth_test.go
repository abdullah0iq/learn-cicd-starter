package auth

import (
	"errors"
	"net/http"
	"testing"
)

// Mock error for missing Authorization header

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		{
			name:    "Missing Authorization Header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header (Wrong Prefix)",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Header (No API Key)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			// Check if returned API Key is correct
			if gotKey != tt.wantKey {
				t.Errorf("Expected key %q, but got %q", tt.wantKey, gotKey)
			}

			// Check if error matches expected error
			if (gotErr != nil && tt.wantErr == nil) || (gotErr == nil && tt.wantErr != nil) || (gotErr != nil && gotErr.Error() != tt.wantErr.Error()) {
				t.Errorf("Expected error %q, but got %q", tt.wantErr, gotErr)
			}
		})
	}
}
