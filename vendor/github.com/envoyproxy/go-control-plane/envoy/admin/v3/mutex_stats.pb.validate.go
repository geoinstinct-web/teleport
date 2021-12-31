// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/admin/v3/mutex_stats.proto

package envoy_admin_v3

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang/protobuf/ptypes"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = ptypes.DynamicAny{}
)

// Validate checks the field values on MutexStats with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *MutexStats) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for NumContentions

	// no validation rules for CurrentWaitCycles

	// no validation rules for LifetimeWaitCycles

	return nil
}

// MutexStatsValidationError is the validation error returned by
// MutexStats.Validate if the designated constraints aren't met.
type MutexStatsValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e MutexStatsValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e MutexStatsValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e MutexStatsValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e MutexStatsValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e MutexStatsValidationError) ErrorName() string { return "MutexStatsValidationError" }

// Error satisfies the builtin error interface
func (e MutexStatsValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMutexStats.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = MutexStatsValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = MutexStatsValidationError{}
