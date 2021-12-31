// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/type/matcher/v3/metadata.proto

package envoy_type_matcher_v3

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

// Validate checks the field values on MetadataMatcher with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *MetadataMatcher) Validate() error {
	if m == nil {
		return nil
	}

	if utf8.RuneCountInString(m.GetFilter()) < 1 {
		return MetadataMatcherValidationError{
			field:  "Filter",
			reason: "value length must be at least 1 runes",
		}
	}

	if len(m.GetPath()) < 1 {
		return MetadataMatcherValidationError{
			field:  "Path",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetPath() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return MetadataMatcherValidationError{
					field:  fmt.Sprintf("Path[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if m.GetValue() == nil {
		return MetadataMatcherValidationError{
			field:  "Value",
			reason: "value is required",
		}
	}

	if v, ok := interface{}(m.GetValue()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return MetadataMatcherValidationError{
				field:  "Value",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// MetadataMatcherValidationError is the validation error returned by
// MetadataMatcher.Validate if the designated constraints aren't met.
type MetadataMatcherValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e MetadataMatcherValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e MetadataMatcherValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e MetadataMatcherValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e MetadataMatcherValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e MetadataMatcherValidationError) ErrorName() string { return "MetadataMatcherValidationError" }

// Error satisfies the builtin error interface
func (e MetadataMatcherValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMetadataMatcher.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = MetadataMatcherValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = MetadataMatcherValidationError{}

// Validate checks the field values on MetadataMatcher_PathSegment with the
// rules defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *MetadataMatcher_PathSegment) Validate() error {
	if m == nil {
		return nil
	}

	switch m.Segment.(type) {

	case *MetadataMatcher_PathSegment_Key:

		if utf8.RuneCountInString(m.GetKey()) < 1 {
			return MetadataMatcher_PathSegmentValidationError{
				field:  "Key",
				reason: "value length must be at least 1 runes",
			}
		}

	default:
		return MetadataMatcher_PathSegmentValidationError{
			field:  "Segment",
			reason: "value is required",
		}

	}

	return nil
}

// MetadataMatcher_PathSegmentValidationError is the validation error returned
// by MetadataMatcher_PathSegment.Validate if the designated constraints
// aren't met.
type MetadataMatcher_PathSegmentValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e MetadataMatcher_PathSegmentValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e MetadataMatcher_PathSegmentValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e MetadataMatcher_PathSegmentValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e MetadataMatcher_PathSegmentValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e MetadataMatcher_PathSegmentValidationError) ErrorName() string {
	return "MetadataMatcher_PathSegmentValidationError"
}

// Error satisfies the builtin error interface
func (e MetadataMatcher_PathSegmentValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMetadataMatcher_PathSegment.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = MetadataMatcher_PathSegmentValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = MetadataMatcher_PathSegmentValidationError{}
