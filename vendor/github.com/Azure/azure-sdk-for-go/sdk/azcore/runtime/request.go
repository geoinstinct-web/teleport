//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"reflect"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/pipeline"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/shared"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// Pipeline represents a primitive for sending HTTP requests and receiving responses.
// Its behavior can be extended by specifying policies during construction.
type Pipeline = pipeline.Pipeline

// Base64Encoding is usesd to specify which base-64 encoder/decoder to use when
// encoding/decoding a slice of bytes to/from a string.
type Base64Encoding int

const (
	// Base64StdFormat uses base64.StdEncoding for encoding and decoding payloads.
	Base64StdFormat Base64Encoding = 0

	// Base64URLFormat uses base64.RawURLEncoding for encoding and decoding payloads.
	Base64URLFormat Base64Encoding = 1
)

// NewRequest creates a new policy.Request with the specified input.
func NewRequest(ctx context.Context, httpMethod string, endpoint string) (*pipeline.Request, error) {
	return pipeline.NewRequest(ctx, httpMethod, endpoint)
}

// NewPipeline creates a new Pipeline object from the specified Transport and Policies.
// If no transport is provided then the default *http.Client transport will be used.
func NewPipeline(transport pipeline.Transporter, policies ...pipeline.Policy) pipeline.Pipeline {
	if transport == nil {
		transport = defaultHTTPClient
	}
	// transport policy must always be the last in the slice
	policies = append(policies, pipeline.PolicyFunc(httpHeaderPolicy), pipeline.PolicyFunc(bodyDownloadPolicy))
	return pipeline.NewPipeline(transport, policies...)
}

// JoinPaths concatenates multiple URL path segments into one path,
// inserting path separation characters as required. JoinPaths will preserve
// query parameters in the root path
func JoinPaths(root string, paths ...string) string {
	if len(paths) == 0 {
		return root
	}

	qps := ""
	if strings.Contains(root, "?") {
		splitPath := strings.Split(root, "?")
		root, qps = splitPath[0], splitPath[1]
	}

	for i := 0; i < len(paths); i++ {
		root = strings.TrimRight(root, "/")
		paths[i] = strings.TrimLeft(paths[i], "/")
		root += "/" + paths[i]
	}

	if qps != "" {
		if !strings.HasSuffix(root, "/") {
			root += "/"
		}
		return root + "?" + qps
	}
	return root
}

// EncodeByteArray will base-64 encode the byte slice v.
func EncodeByteArray(v []byte, format Base64Encoding) string {
	if format == Base64URLFormat {
		return base64.RawURLEncoding.EncodeToString(v)
	}
	return base64.StdEncoding.EncodeToString(v)
}

// MarshalAsByteArray will base-64 encode the byte slice v, then calls SetBody.
// The encoded value is treated as a JSON string.
func MarshalAsByteArray(req *policy.Request, v []byte, format Base64Encoding) error {
	// send as a JSON string
	encode := fmt.Sprintf("\"%s\"", EncodeByteArray(v, format))
	return req.SetBody(shared.NopCloser(strings.NewReader(encode)), shared.ContentTypeAppJSON)
}

// MarshalAsJSON calls json.Marshal() to get the JSON encoding of v then calls SetBody.
func MarshalAsJSON(req *policy.Request, v interface{}) error {
	v = cloneWithoutReadOnlyFields(v)
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("error marshalling type %T: %s", v, err)
	}
	return req.SetBody(shared.NopCloser(bytes.NewReader(b)), shared.ContentTypeAppJSON)
}

// MarshalAsXML calls xml.Marshal() to get the XML encoding of v then calls SetBody.
func MarshalAsXML(req *policy.Request, v interface{}) error {
	b, err := xml.Marshal(v)
	if err != nil {
		return fmt.Errorf("error marshalling type %T: %s", v, err)
	}
	return req.SetBody(shared.NopCloser(bytes.NewReader(b)), shared.ContentTypeAppXML)
}

// SetMultipartFormData writes the specified keys/values as multi-part form
// fields with the specified value.  File content must be specified as a ReadSeekCloser.
// All other values are treated as string values.
func SetMultipartFormData(req *policy.Request, formData map[string]interface{}) error {
	body := bytes.Buffer{}
	writer := multipart.NewWriter(&body)
	for k, v := range formData {
		if rsc, ok := v.(io.ReadSeekCloser); ok {
			// this is the body to upload, the key is its file name
			fd, err := writer.CreateFormFile(k, k)
			if err != nil {
				return err
			}
			// copy the data to the form file
			if _, err = io.Copy(fd, rsc); err != nil {
				return err
			}
			continue
		}
		// ensure the value is in string format
		s, ok := v.(string)
		if !ok {
			s = fmt.Sprintf("%v", v)
		}
		if err := writer.WriteField(k, s); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return req.SetBody(shared.NopCloser(bytes.NewReader(body.Bytes())), writer.FormDataContentType())
}

// returns a clone of the object graph pointed to by v, omitting values of all read-only
// fields. if there are no read-only fields in the object graph, no clone is created.
func cloneWithoutReadOnlyFields(v interface{}) interface{} {
	val := reflect.Indirect(reflect.ValueOf(v))
	if val.Kind() != reflect.Struct {
		// not a struct, skip
		return v
	}
	// first walk the graph to find any R/O fields.
	// if there aren't any, skip cloning the graph.
	if !recursiveFindReadOnlyField(val) {
		return v
	}
	return recursiveCloneWithoutReadOnlyFields(val)
}

// returns true if any field in the object graph of val contains the `azure:"ro"` tag value
func recursiveFindReadOnlyField(val reflect.Value) bool {
	t := val.Type()
	// iterate over the fields, looking for the "azure" tag.
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		aztag := field.Tag.Get("azure")
		if azureTagIsReadOnly(aztag) {
			return true
		} else if reflect.Indirect(val.Field(i)).Kind() == reflect.Struct && recursiveFindReadOnlyField(reflect.Indirect(val.Field(i))) {
			return true
		}
	}
	return false
}

// clones the object graph of val.  all non-R/O properties are copied to the clone
func recursiveCloneWithoutReadOnlyFields(val reflect.Value) interface{} {
	clone := reflect.New(val.Type())
	t := val.Type()
	// iterate over the fields, looking for the "azure" tag.
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		aztag := field.Tag.Get("azure")
		if azureTagIsReadOnly(aztag) {
			// omit from payload
		} else if reflect.Indirect(val.Field(i)).Kind() == reflect.Struct {
			// recursive case
			v := recursiveCloneWithoutReadOnlyFields(reflect.Indirect(val.Field(i)))
			if t.Field(i).Anonymous {
				// NOTE: this does not handle the case of embedded fields of unexported struct types.
				// this should be ok as we don't generate any code like this at present
				reflect.Indirect(clone).Field(i).Set(reflect.Indirect(reflect.ValueOf(v)))
			} else {
				reflect.Indirect(clone).Field(i).Set(reflect.ValueOf(v))
			}
		} else {
			// no azure RO tag, non-recursive case, include in payload
			reflect.Indirect(clone).Field(i).Set(val.Field(i))
		}
	}
	return clone.Interface()
}

// returns true if the "azure" tag contains the option "ro"
func azureTagIsReadOnly(tag string) bool {
	if tag == "" {
		return false
	}
	parts := strings.Split(tag, ",")
	for _, part := range parts {
		if part == "ro" {
			return true
		}
	}
	return false
}
