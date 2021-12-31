// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/trace/v3/datadog.proto

package envoy_config_trace_v3

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

// Validate checks the field values on DatadogConfig with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *DatadogConfig) Validate() error {
	if m == nil {
		return nil
	}

	if utf8.RuneCountInString(m.GetCollectorCluster()) < 1 {
		return DatadogConfigValidationError{
			field:  "CollectorCluster",
			reason: "value length must be at least 1 runes",
		}
	}

	if utf8.RuneCountInString(m.GetServiceName()) < 1 {
		return DatadogConfigValidationError{
			field:  "ServiceName",
			reason: "value length must be at least 1 runes",
		}
	}

	return nil
}

// DatadogConfigValidationError is the validation error returned by
// DatadogConfig.Validate if the designated constraints aren't met.
type DatadogConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e DatadogConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e DatadogConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e DatadogConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e DatadogConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e DatadogConfigValidationError) ErrorName() string { return "DatadogConfigValidationError" }

// Error satisfies the builtin error interface
func (e DatadogConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDatadogConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = DatadogConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = DatadogConfigValidationError{}
