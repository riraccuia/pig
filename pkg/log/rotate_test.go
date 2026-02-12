package log

import "testing"

func TestRotateSizeFromRotateString_ValidSizes(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    int64
		wantErr bool
	}{
		{
			name:  "int64 passthrough",
			input: int64(2048),
			want:  2048,
		},
		{
			name:  "empty string uses default size",
			input: "",
			want:  5 * 1024 * 1024,
		},
		{
			name:  "kilobytes",
			input: "100k",
			want:  100 * 1024,
		},
		{
			name:  "megabytes",
			input: "1m",
			want:  1 * 1024 * 1024,
		},
		{
			name:  "gigabytes",
			input: "2g",
			want:  2 * 1024 * 1024 * 1024,
		},
		{
			name:    "invalid input",
			input:   []int{123},
			wantErr: true,
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RotateSizeFromRotateString(tt.input)
			if err != nil && !tt.wantErr {
				t.Fatalf("RotateSizeFromRotateString(%v) returned error: %v", tt.input, err)
			}

			if got != tt.want {
				t.Fatalf("RotateSizeFromRotateString(%v) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
