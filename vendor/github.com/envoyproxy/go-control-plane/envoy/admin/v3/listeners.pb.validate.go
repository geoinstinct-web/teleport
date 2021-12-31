// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/admin/v3/listeners.proto

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

// Validate checks the field values on Listeners with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *Listeners) Validate() error {
	if m == nil {
		return nil
	}

	for idx, item := range m.GetListenerStatuses() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ListenersValidationError{
					field:  fmt.Sprintf("ListenerStatuses[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// ListenersValidationError is the validation error returned by
// Listeners.Validate if the designated constraints aren't met.
type ListenersValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListenersValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListenersValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListenersValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListenersValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListenersValidationError) ErrorName() string { return "ListenersValidationError" }

// Error satisfies the builtin error interface
func (e ListenersValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListeners.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListenersValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListenersValidationError{}

// Validate checks the field values on ListenerStatus with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *ListenerStatus) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Name

	if v, ok := interface{}(m.GetLocalAddress()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ListenerStatusValidationError{
				field:  "LocalAddress",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// ListenerStatusValidationError is the validation error returned by
// ListenerStatus.Validate if the designated constraints aren't met.
type ListenerStatusValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListenerStatusValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListenerStatusValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListenerStatusValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListenerStatusValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListenerStatusValidationError) ErrorName() string { return "ListenerStatusValidationError" }

// Error satisfies the builtin error interface
func (e ListenerStatusValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListenerStatus.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListenerStatusValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListenerStatusValidationError{}
