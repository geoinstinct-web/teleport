// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/api/v2/scoped_route.proto

package envoy_api_v2

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

// Validate checks the field values on ScopedRouteConfiguration with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *ScopedRouteConfiguration) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetName()) < 1 {
		return ScopedRouteConfigurationValidationError{
			field:  "Name",
			reason: "value length must be at least 1 bytes",
		}
	}

	if len(m.GetRouteConfigurationName()) < 1 {
		return ScopedRouteConfigurationValidationError{
			field:  "RouteConfigurationName",
			reason: "value length must be at least 1 bytes",
		}
	}

	if m.GetKey() == nil {
		return ScopedRouteConfigurationValidationError{
			field:  "Key",
			reason: "value is required",
		}
	}

	if v, ok := interface{}(m.GetKey()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ScopedRouteConfigurationValidationError{
				field:  "Key",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// ScopedRouteConfigurationValidationError is the validation error returned by
// ScopedRouteConfiguration.Validate if the designated constraints aren't met.
type ScopedRouteConfigurationValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ScopedRouteConfigurationValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ScopedRouteConfigurationValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ScopedRouteConfigurationValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ScopedRouteConfigurationValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ScopedRouteConfigurationValidationError) ErrorName() string {
	return "ScopedRouteConfigurationValidationError"
}

// Error satisfies the builtin error interface
func (e ScopedRouteConfigurationValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sScopedRouteConfiguration.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ScopedRouteConfigurationValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ScopedRouteConfigurationValidationError{}

// Validate checks the field values on ScopedRouteConfiguration_Key with the
// rules defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *ScopedRouteConfiguration_Key) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetFragments()) < 1 {
		return ScopedRouteConfiguration_KeyValidationError{
			field:  "Fragments",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetFragments() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ScopedRouteConfiguration_KeyValidationError{
					field:  fmt.Sprintf("Fragments[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// ScopedRouteConfiguration_KeyValidationError is the validation error returned
// by ScopedRouteConfiguration_Key.Validate if the designated constraints
// aren't met.
type ScopedRouteConfiguration_KeyValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ScopedRouteConfiguration_KeyValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ScopedRouteConfiguration_KeyValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ScopedRouteConfiguration_KeyValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ScopedRouteConfiguration_KeyValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ScopedRouteConfiguration_KeyValidationError) ErrorName() string {
	return "ScopedRouteConfiguration_KeyValidationError"
}

// Error satisfies the builtin error interface
func (e ScopedRouteConfiguration_KeyValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sScopedRouteConfiguration_Key.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ScopedRouteConfiguration_KeyValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ScopedRouteConfiguration_KeyValidationError{}

// Validate checks the field values on ScopedRouteConfiguration_Key_Fragment
// with the rules defined in the proto definition for this message. If any
// rules are violated, an error is returned.
func (m *ScopedRouteConfiguration_Key_Fragment) Validate() error {
	if m == nil {
		return nil
	}

	switch m.Type.(type) {

	case *ScopedRouteConfiguration_Key_Fragment_StringKey:
		// no validation rules for StringKey

	default:
		return ScopedRouteConfiguration_Key_FragmentValidationError{
			field:  "Type",
			reason: "value is required",
		}

	}

	return nil
}

// ScopedRouteConfiguration_Key_FragmentValidationError is the validation error
// returned by ScopedRouteConfiguration_Key_Fragment.Validate if the
// designated constraints aren't met.
type ScopedRouteConfiguration_Key_FragmentValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ScopedRouteConfiguration_Key_FragmentValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ScopedRouteConfiguration_Key_FragmentValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ScopedRouteConfiguration_Key_FragmentValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ScopedRouteConfiguration_Key_FragmentValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ScopedRouteConfiguration_Key_FragmentValidationError) ErrorName() string {
	return "ScopedRouteConfiguration_Key_FragmentValidationError"
}

// Error satisfies the builtin error interface
func (e ScopedRouteConfiguration_Key_FragmentValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sScopedRouteConfiguration_Key_Fragment.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ScopedRouteConfiguration_Key_FragmentValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ScopedRouteConfiguration_Key_FragmentValidationError{}
