package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTrimDurationSuffix(t *testing.T) {
	t.Parallel()
	var testCases = []struct {
		comment string
		ts      time.Duration
		wantFmt string
	}{
		{
			comment: "trim minutes/seconds",
			ts:      time.Duration(1 * time.Hour),
			wantFmt: "1h",
		},
		{
			comment: "trim seconds",
			ts:      time.Duration(1 * time.Minute),
			wantFmt: "1m",
		},
		{
			comment: "does not trim non-zero suffix",
			ts:      time.Duration(90 * time.Second),
			wantFmt: "1m30s",
		},
		{
			comment: "does not trim zero in the middle",
			ts:      time.Duration(3630 * time.Second),
			wantFmt: "1h0m30s",
		},
	}
	for _, tt := range testCases {
		tt := tt
		t.Run(tt.comment, func(t *testing.T) {
			fmt := trimDurationZeroSuffix(tt.ts)
			require.Equal(t, fmt, tt.wantFmt)
		})
	}
}
