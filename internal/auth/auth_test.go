package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	testCases := []struct {
		name        string
		inputHeader http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name: "Valid Header - Correct API Key",
			inputHeader: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			expectedKey: "my-secret-api-key",
			expectedErr: nil,
		},
		{
			name:        "No Header - Error expected",
			inputHeader: http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header - Wrong Scheme",
			inputHeader: http.Header{
				"Authorization": []string{"Bearer my-secret-api-key"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Header - No API Key",
			inputHeader: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Header - No Space",
			inputHeader: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "Edge Case - Case-sensitive scheme",
			inputHeader: http.Header{
				"Authorization": []string{"apikey my-secret-api-key"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tc.inputHeader)

			if apiKey != tc.expectedKey {
				t.Errorf("expected key '%s', but got '%s'", tc.expectedKey, apiKey)
			}

			if tc.expectedErr != nil {
				if err == nil {
					t.Errorf("expected error '%v', but got nil", tc.expectedErr)
					return
				}
				if err.Error() != tc.expectedErr.Error() {
					t.Errorf("expected error '%v', but got '%v'", tc.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, but got '%v'", err)
				}
			}
		})
	}
}
