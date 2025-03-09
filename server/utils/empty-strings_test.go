package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoveEmptyStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "No Empty Strings",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Some Empty Strings",
			input:    []string{"a", "", "b", "", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "All Empty Strings",
			input:    []string{"", "", ""},
			expected: []string{},
		},
		{
			name:     "Empty Input",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "Whitespace Strings",
			input:    []string{" ", "  ", "a"},
			expected: []string{" ", "  ", "a"}, // Whitespace not considered empty
		},
		{
			name:     "Mix of Values",
			input:    []string{"", "hello", "", "world", ""},
			expected: []string{"hello", "world"},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := RemoveEmptyStrings(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
