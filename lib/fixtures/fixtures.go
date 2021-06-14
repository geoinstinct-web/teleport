package fixtures

import (
	"reflect"
	"runtime/debug"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/gravitational/trace"
	"github.com/kylelemons/godebug/diff"
	check "gopkg.in/check.v1"
)

// ExpectNotFound expects not found error
func ExpectNotFound(c *check.C, err error) {
	c.Assert(trace.IsNotFound(err), check.Equals, true, check.Commentf("expected NotFound, got %T %v at %v", trace.Unwrap(err), err, string(debug.Stack())))
}

// ExpectBadParameter expects bad parameter error
func ExpectBadParameter(c *check.C, err error) {
	c.Assert(trace.IsBadParameter(err), check.Equals, true, check.Commentf("expected BadParameter, got %T %v at %v", trace.Unwrap(err), err, string(debug.Stack())))
}

// ExpectCompareFailed expects compare failed error
func ExpectCompareFailed(c *check.C, err error) {
	c.Assert(trace.IsCompareFailed(err), check.Equals, true, check.Commentf("expected CompareFailed, got %T %v at %v", trace.Unwrap(err), err, string(debug.Stack())))
}

// ExpectAccessDenied expects error to be access denied
func ExpectAccessDenied(c *check.C, err error) {
	c.Assert(trace.IsAccessDenied(err), check.Equals, true, check.Commentf("expected AccessDenied, got %T %v at %v", trace.Unwrap(err), err, string(debug.Stack())))
}

// ExpectAlreadyExists expects already exists error
func ExpectAlreadyExists(c *check.C, err error) {
	c.Assert(trace.IsAlreadyExists(err), check.Equals, true, check.Commentf("expected AlreadyExists, got %T %v at %v", trace.Unwrap(err), err, string(debug.Stack())))
}

// ExpectConnectionProblem expects connection problem error
func ExpectConnectionProblem(c *check.C, err error) {
	c.Assert(trace.IsConnectionProblem(err), check.Equals, true, check.Commentf("expected ConnectionProblem, got %T %v at %v", trace.Unwrap(err), err, string(debug.Stack())))
}

// ExpectLimitExceeded expects limit exceeded error
func ExpectLimitExceeded(c *check.C, err error) {
	c.Assert(trace.IsLimitExceeded(err), check.Equals, true, check.Commentf("expected LimitExceeded, got %T %v at %v", trace.Unwrap(err), err, string(debug.Stack())))
}

// AssertNotFound expects not found error
func AssertNotFound(t *testing.T, err error) {
	if trace.IsNotFound(err) == false {
		t.Fatalf("Expected NotFound, got %T %v at %v.", trace.Unwrap(err), err, string(debug.Stack()))
	}
}

// AssertBadParameter expects bad parameter error
func AssertBadParameter(t *testing.T, err error) {
	if trace.IsBadParameter(err) == false {
		t.Fatalf("Expected BadParameter, got %T %v at %v.", trace.Unwrap(err), err, string(debug.Stack()))
	}
}

// AssertCompareFailed expects compare failed error
func AssertCompareFailed(t *testing.T, err error) {
	if trace.IsCompareFailed(err) == false {
		t.Fatalf("Expected CompareFailed, got %T %v at %v.", trace.Unwrap(err), err, string(debug.Stack()))
	}
}

// AssertAccessDenied expects error to be access denied
func AssertAccessDenied(t *testing.T, err error) {
	if trace.IsAccessDenied(err) == false {
		t.Fatalf("Expected AccessDenied, got %T %v at %v.", trace.Unwrap(err), err, string(debug.Stack()))
	}
}

// AssertAlreadyExists expects already exists error
func AssertAlreadyExists(t *testing.T, err error) {
	if trace.IsAlreadyExists(err) == false {
		t.Fatalf("Expected AlreadyExists, got %T %v at %v.", trace.Unwrap(err), err, string(debug.Stack()))
	}
}

// AssertConnectionProblem expects connection problem error
func AssertConnectionProblem(t *testing.T, err error) {
	if trace.IsConnectionProblem(err) == false {
		t.Fatalf("Expected ConnectionProblem, got %T %v at %v.", trace.Unwrap(err), err, string(debug.Stack()))
	}
}

// DeepCompare uses gocheck DeepEquals but provides nice diff if things are not equal
func DeepCompare(c *check.C, a, b interface{}) {
	d := &spew.ConfigState{Indent: " ", DisableMethods: true, DisablePointerMethods: true, DisablePointerAddresses: true}

	if !reflect.DeepEqual(a, b) {
		c.Fatalf("Values are not equal\n%v\nStack:\n%v\n", diff.Diff(d.Sdump(a), d.Sdump(b)), string(debug.Stack()))
	}
}

// DeepCompareSlices compares two slices
func DeepCompareSlices(c *check.C, a, b interface{}) {
	aval, bval := reflect.ValueOf(a), reflect.ValueOf(b)
	if aval.Kind() != reflect.Slice {
		c.Fatalf("%v is not a map, %T", a, a)
	}

	if bval.Kind() != reflect.Slice {
		c.Fatalf("%v is not a map, %T", b, b)
	}

	if aval.Len() != bval.Len() {
		c.Fatalf("slices have different length of %v and %v", aval.Len(), bval.Len())
	}

	for i := 0; i < aval.Len(); i++ {
		DeepCompare(c, aval.Index(i).Interface(), bval.Index(i).Interface())
	}
}

// DeepCompareMaps compares two maps
func DeepCompareMaps(c *check.C, a, b interface{}) {
	aval, bval := reflect.ValueOf(a), reflect.ValueOf(b)
	if aval.Kind() != reflect.Map {
		c.Fatalf("%v is not a map, %T", a, a)
	}

	if bval.Kind() != reflect.Map {
		c.Fatalf("%v is not a map, %T", b, b)
	}

	for _, k := range aval.MapKeys() {
		vala := aval.MapIndex(k)
		valb := bval.MapIndex(k)

		if !vala.IsValid() {
			c.Fatalf("expected valid value for %v in %v", k.Interface(), a)
		}

		if !valb.IsValid() {
			c.Fatalf("key %v is found in %v, but not in %v", k.Interface(), a, b)
		}
	}

	for _, k := range bval.MapKeys() {
		vala := aval.MapIndex(k)
		valb := bval.MapIndex(k)

		if !valb.IsValid() {
			c.Fatalf("expected valid value for %v in %v", k.Interface(), a)
		}

		if !vala.IsValid() {
			c.Fatalf("key %v is found in %v, but not in %v", k.Interface(), a, b)
		}

		if reflect.ValueOf(vala.Interface()).Kind() == reflect.Map {
			DeepCompareMaps(c, vala.Interface(), valb.Interface())
		} else {
			DeepCompare(c, vala.Interface(), valb.Interface())
		}
	}
}

const SAMLOktaAuthRequestID = `_4d84cad1-1c61-4e4f-8ab6-1358b8d0da77`
const SAMLOktaAuthnResponseXML = `<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://localhost:3080/v1/webapi/saml/acs" ID="id23076376064475199270314772" InResponseTo="_4d84cad1-1c61-4e4f-8ab6-1358b8d0da77" IssueInstant="2017-05-10T18:52:44.797Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exkafftca6RqPVgyZ0h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id23076376064475199270314772"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>wvBbayjxY78ouyo1DYjGrAOfLYymapbZeylWWnbA+lQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>QSKPoRIEwjNw/QT3GO3huhdE0seUqSrWvZWIFwkAZv3D04Q5SgsiKHJbP22VsaMUVWojnYbzLfk62nnCSPvdnJmCEH7N3SV+3TkTfeJrCOqi34NLwHadBNTSURnFA+Y+p+HNYE4x4vtg8Vn5KF/teM9hMwAEqKimobYRIS3fPW8jVRcMBdkki5HaM3OCXy9JL1krTkFMGmHobeoaV4taIv7lDpfPw9fRuys1oX0VKfGXmVMpG24n1KB8jLOuC9GYL4HdB9LhIHfznzW3xiKVXm4rJiVIg9PMSQ6SV698yFXEjh5DOdLZPIz5qcizkiL7jujPUSwZQSTArp4m6ft3Pw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVvvlUB6MA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi04MTMzNTQxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTcwNTA5MjMzODQ3WhcNMjcwNTA5MjMzOTQ3WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtODEzMzU0MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
ltQB+ZTGKoaNiWQRZ/bzl9oNmbjFyLiVlDASaYnuv1yBx70/Tzr9VXn0gWkl5yH0zIpzREvR5qM1
VAaH3dgNbxTg15f0e5xDk7r5ggS11mX5p8S1Ca9UQmqhRRv7jhMJxHbCy4rFV5jO/uyNQDaMZLPd
zFuzpwKaWhy/UCQ3lDmNzxp3Q6T3FULV+fvs7tJp+8p6qfpoGkANGVfs/Jx/kgbbk0JZG2wk4VVl
b1rZTZJWQ6hCLwTAsD/WixcUx1BFTXmqoZTYNETATVJQ+bEMCVf8K4hxbH6hEgjoL//AE9zgpa1m
uvKwevYBvYZ/+VRy+It3d9mq73AdrG9vchE3qQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQASANAj
8JQdBdKIrrbU6n1egwETwkOUwWyUja/5t+C/RIZPuKP5XmsUhFecbCrML2+M7HG0l5leqyD3u5pS
yhyBz99QWZegoRJy05tciuQUCyPrp6zDzl5De3byq5WQ6Ke+uiRb2GFdDNDhLuMlE48aLWyjm4qh
31Q0/wAWJ1zwmrYxu4p/OhZemU7myuSF5tp35rzV3CPRN31d2UcZAwzMUgwKkCE3yT1o+lLskg/k
C7yZIZM0DuazwkaenExrncvPtF6KL7eccudcknNjhRjFD3Yx1nNXgbVRHvVaElm0YxLiLcl8l0Rn
pHM7WKwFyW1dvEDax3BGj9/cbKvpvcwR</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id23076376064501965895215823" IssueInstant="2017-05-10T18:52:44.797Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exkafftca6RqPVgyZ0h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id23076376064501965895215823"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>Bg7B7U6pHc0PU91Ed768yrae+kU0ZgZoafKTj1oJZ10=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>GBN1oQJm1Yk4Icq9vb/6YASjQtYof3yJTSvd8uMc9NgQ6qOfkkw+QMNiqPeoHdaPfUiwKyZQrIynsjMMlRzBe/0zEbrP67wseAxPTIKFgbWPk/X2WUbtU3Jg5ijtUWawmoIoChMqZhxkm/rc/7zgRfNFZWGmucgk/GzxzhJb0n3ZtDiG2ZqI7tAnp3O5Oc8rMorYCun1sV/bm+k9HTwNOUaBSjm/d0BjWDfWCtl4KOlC9XHDg7Ht1i++Vjz5Dqt4/JkGUy8LrmLxep3ifXakRwDgK7qlDBRTKU9Up4vTwUPxWprgLZ0u0ze7h7DNwYCLfGC48X6MlaH+tbhklocsjg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVvvlUB6MA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi04MTMzNTQxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTcwNTA5MjMzODQ3WhcNMjcwNTA5MjMzOTQ3WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtODEzMzU0MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
ltQB+ZTGKoaNiWQRZ/bzl9oNmbjFyLiVlDASaYnuv1yBx70/Tzr9VXn0gWkl5yH0zIpzREvR5qM1
VAaH3dgNbxTg15f0e5xDk7r5ggS11mX5p8S1Ca9UQmqhRRv7jhMJxHbCy4rFV5jO/uyNQDaMZLPd
zFuzpwKaWhy/UCQ3lDmNzxp3Q6T3FULV+fvs7tJp+8p6qfpoGkANGVfs/Jx/kgbbk0JZG2wk4VVl
b1rZTZJWQ6hCLwTAsD/WixcUx1BFTXmqoZTYNETATVJQ+bEMCVf8K4hxbH6hEgjoL//AE9zgpa1m
uvKwevYBvYZ/+VRy+It3d9mq73AdrG9vchE3qQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQASANAj
8JQdBdKIrrbU6n1egwETwkOUwWyUja/5t+C/RIZPuKP5XmsUhFecbCrML2+M7HG0l5leqyD3u5pS
yhyBz99QWZegoRJy05tciuQUCyPrp6zDzl5De3byq5WQ6Ke+uiRb2GFdDNDhLuMlE48aLWyjm4qh
31Q0/wAWJ1zwmrYxu4p/OhZemU7myuSF5tp35rzV3CPRN31d2UcZAwzMUgwKkCE3yT1o+lLskg/k
C7yZIZM0DuazwkaenExrncvPtF6KL7eccudcknNjhRjFD3Yx1nNXgbVRHvVaElm0YxLiLcl8l0Rn
pHM7WKwFyW1dvEDax3BGj9/cbKvpvcwR</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">ops@gravitational.io</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_4d84cad1-1c61-4e4f-8ab6-1358b8d0da77" NotOnOrAfter="2017-05-10T18:57:44.797Z" Recipient="https://localhost:3080/v1/webapi/saml/acs"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2017-05-10T18:47:44.797Z" NotOnOrAfter="2017-05-10T18:57:44.797Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AudienceRestriction><saml2:Audience>https://localhost:3080/v1/webapi/saml/acs</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2017-05-10T18:42:30.615Z" SessionIndex="_4d84cad1-1c61-4e4f-8ab6-1358b8d0da77" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Attribute Name="groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Everyone</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`

const SAMLOktaCertPEM = `-----BEGIN CERTIFICATE-----
MIIDpDCCAoygAwIBAgIGAVvvlUB6MA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi04MTMzNTQxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTcwNTA5MjMzODQ3WhcNMjcwNTA5MjMzOTQ3WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtODEzMzU0MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
ltQB+ZTGKoaNiWQRZ/bzl9oNmbjFyLiVlDASaYnuv1yBx70/Tzr9VXn0gWkl5yH0zIpzREvR5qM1
VAaH3dgNbxTg15f0e5xDk7r5ggS11mX5p8S1Ca9UQmqhRRv7jhMJxHbCy4rFV5jO/uyNQDaMZLPd
zFuzpwKaWhy/UCQ3lDmNzxp3Q6T3FULV+fvs7tJp+8p6qfpoGkANGVfs/Jx/kgbbk0JZG2wk4VVl
b1rZTZJWQ6hCLwTAsD/WixcUx1BFTXmqoZTYNETATVJQ+bEMCVf8K4hxbH6hEgjoL//AE9zgpa1m
uvKwevYBvYZ/+VRy+It3d9mq73AdrG9vchE3qQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQASANAj
8JQdBdKIrrbU6n1egwETwkOUwWyUja/5t+C/RIZPuKP5XmsUhFecbCrML2+M7HG0l5leqyD3u5pS
yhyBz99QWZegoRJy05tciuQUCyPrp6zDzl5De3byq5WQ6Ke+uiRb2GFdDNDhLuMlE48aLWyjm4qh
31Q0/wAWJ1zwmrYxu4p/OhZemU7myuSF5tp35rzV3CPRN31d2UcZAwzMUgwKkCE3yT1o+lLskg/k
C7yZIZM0DuazwkaenExrncvPtF6KL7eccudcknNjhRjFD3Yx1nNXgbVRHvVaElm0YxLiLcl8l0Rn
pHM7WKwFyW1dvEDax3BGj9/cbKvpvcwR
-----END CERTIFICATE-----`

const SAMLOktaSSO = `https://dev-813354.oktapreview.com/app/gravitationaldev813354_teleportsaml_1/exkafftca6RqPVgyZ0h7/sso/saml`

const SAMLOktaConnectorV2 = `kind: saml
version: v2
metadata:
  name: OktaSAML
  namespace: default
spec:
  acs: https://localhost:3080/v1/webapi/saml/acs
  attributes_to_roles:
    - {name: "groups", value: "Everyone", roles: ["admin"]}
  entity_descriptor: |
    <?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/exkafftca6RqPVgyZ0h7"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVvvlUB6MA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
    A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
    MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi04MTMzNTQxHDAaBgkqhkiG9w0BCQEW
    DWluZm9Ab2t0YS5jb20wHhcNMTcwNTA5MjMzODQ3WhcNMjcwNTA5MjMzOTQ3WjCBkjELMAkGA1UE
    BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
    BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtODEzMzU0MRwwGgYJ
    KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
    ltQB+ZTGKoaNiWQRZ/bzl9oNmbjFyLiVlDASaYnuv1yBx70/Tzr9VXn0gWkl5yH0zIpzREvR5qM1
    VAaH3dgNbxTg15f0e5xDk7r5ggS11mX5p8S1Ca9UQmqhRRv7jhMJxHbCy4rFV5jO/uyNQDaMZLPd
    zFuzpwKaWhy/UCQ3lDmNzxp3Q6T3FULV+fvs7tJp+8p6qfpoGkANGVfs/Jx/kgbbk0JZG2wk4VVl
    b1rZTZJWQ6hCLwTAsD/WixcUx1BFTXmqoZTYNETATVJQ+bEMCVf8K4hxbH6hEgjoL//AE9zgpa1m
    uvKwevYBvYZ/+VRy+It3d9mq73AdrG9vchE3qQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQASANAj
    8JQdBdKIrrbU6n1egwETwkOUwWyUja/5t+C/RIZPuKP5XmsUhFecbCrML2+M7HG0l5leqyD3u5pS
    yhyBz99QWZegoRJy05tciuQUCyPrp6zDzl5De3byq5WQ6Ke+uiRb2GFdDNDhLuMlE48aLWyjm4qh
    31Q0/wAWJ1zwmrYxu4p/OhZemU7myuSF5tp35rzV3CPRN31d2UcZAwzMUgwKkCE3yT1o+lLskg/k
    C7yZIZM0DuazwkaenExrncvPtF6KL7eccudcknNjhRjFD3Yx1nNXgbVRHvVaElm0YxLiLcl8l0Rn
    pHM7WKwFyW1dvEDax3BGj9/cbKvpvcwR</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dev-813354.oktapreview.com/app/gravitationaldev813354_teleportsaml_1/exkafftca6RqPVgyZ0h7/sso/saml"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://dev-813354.oktapreview.com/app/gravitationaldev813354_teleportsaml_1/exkafftca6RqPVgyZ0h7/sso/saml"/></md:IDPSSODescriptor></md:EntityDescriptor>`

const SAMLPingConnector = `kind: saml
version: v2
metadata:
  name: ping
spec:
  display: PingID
  provider: ping
  acs: https://proxy.example.com:3080/v1/webapi/saml/acs
  attributes_to_roles:
    - {name: "groups", value: "ping-admin", roles: ["admin"]}
    - {name: "groups", value: "ping-dev", roles: ["dev"]}
  entity_descriptor: |
    <md:EntityDescriptor entityID="https://auth.pingone.com/8be7412d-7d2f-4392-90a4-07458d3dee78" ID="DUp57Bcq-y4RtkrRLyYj2fYxtqR" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data>
              <ds:X509Certificate>MIIDejCCAmKgAwIBAgIGAXnsYbiQMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1QaW5nIElkZW50aXR5MRYwFAYDVQQLDA1QaW5nIElkZW50aXR5MT8wPQYDVQQDDDZQaW5nT25lIFNTTyBDZXJ0aWZpY2F0ZSBmb3IgQWRtaW5pc3RyYXRvcnMgZW52aXJvbm1lbnQwHhcNMjEwNjA4MTYwODE3WhcNMjIwNjA4MTYwODE3WjB+MQswCQYDVQQGEwJVUzEWMBQGA1UECgwNUGluZyBJZGVudGl0eTEWMBQGA1UECwwNUGluZyBJZGVudGl0eTE/MD0GA1UEAww2UGluZ09uZSBTU08gQ2VydGlmaWNhdGUgZm9yIEFkbWluaXN0cmF0b3JzIGVudmlyb25tZW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqJP+9QA8rzt9lLrKQigkT1HxCP5qIQH9vKgIhCDx5q7eSHOlxQ7MMa+1v1WQq1y5mgNG1zxe+cEaJ646JHQLoa0yj+rXsfCsUsKG7qceHzMR8p4y74x77PHTBJEviS9g/+fMGq7eaSK/F8ksPBfBjHnWv+lvnzrAGhxEuBXfFPf5Gb2Vr5LYurZEu9lIdFtSnFCVjzUIC1SMyovl92K4WdJpZ60N8FUSR6Jb7b8gWjnNHNc1iwr5C2b8+HUuWhqCIc0TQygEilZAdJhpYkeCQMiSqySsV+cmJ1vdjsV0HXX0YREDq6koklnw1hyTe1AckcH6qfWyBcoG2VYORjZPQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA0eVvkB+/RSIEs7CXje7KKFGO99X7nIBNcpztp6kevxTDFHKsVlGFfl/mkksw9SjzdWSMDgGxxy6riYnScQD0FdyxaKzM0CRFfqdHf2+qVnK4GbiodqLOVp1dDE6CSQuPp7inQr+JDO/xD1WUAyMSC+ouFRdHq2O7MCYolEcyWiZoTTcch8RhLo5nqueKQfP0vaJwzAPgpXxAuabVuyrtN0BZHixO/sjjg9yup8/esCMBB/RR90PxzbI+8ZX5g1MxZZwSaXauQFyOjm5/t+JEisZf8rzrrhDd2GzWrYngB8DJLxCUK1JTM5SO/k3TqeDHLHi202P7AN2S/1CqzCaGb</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleLogoutService Location="https://auth.pingone.com/8be7412d-7d2f-4392-90a4-07458d3dee78/saml20/idp/slo" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"/>
        <md:SingleLogoutService Location="https://auth.pingone.com/8be7412d-7d2f-4392-90a4-07458d3dee78/saml20/idp/slo" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
        <md:SingleSignOnService Location="https://auth.pingone.com/8be7412d-7d2f-4392-90a4-07458d3dee78/saml20/idp/sso" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
        <md:SingleSignOnService Location="https://auth.pingone.com/8be7412d-7d2f-4392-90a4-07458d3dee78/saml20/idp/sso" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.timezone" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.updatedAt" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.preferredLanguage" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.address.region" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.address.streetAddress" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.address.locality" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.address.postalCode" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.address.countryCode" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.lifecycle.status" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.createdAt" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.locale" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.title" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.externalId" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.memberOfGroupNames" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.verifyStatus" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.population.id" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.identityProvider.type" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.identityProvider.id" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.email" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.photo.href" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.type" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.mfaEnabled" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.id" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.primaryPhone" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.enabled" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.accountId" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.account.unlockAt" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.account.lockedAt" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.account.canAuthenticate" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.account.secondsUntilUnlock" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.account.status" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.nickname" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.name.family" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.name.honorificPrefix" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.name.formatted" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.name.middle" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.name.honorificSuffix" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.name.given" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.memberOfGroupIDs" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.lastSignOn.remoteIp" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.lastSignOn.at" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.username" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
        <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="user.mobilePhone" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>`

const SigningCertPEM = `-----BEGIN CERTIFICATE-----
MIIDKjCCAhKgAwIBAgIQJtJDJZZBkg/afM8d2ZJCTjANBgkqhkiG9w0BAQsFADBA
MRUwEwYDVQQKEwxUZWxlcG9ydCBPU1MxJzAlBgNVBAMTHnRlbGVwb3J0LmxvY2Fs
aG9zdC5sb2NhbGRvbWFpbjAeFw0xNzA1MDkxOTQwMzZaFw0yNzA1MDcxOTQwMzZa
MEAxFTATBgNVBAoTDFRlbGVwb3J0IE9TUzEnMCUGA1UEAxMedGVsZXBvcnQubG9j
YWxob3N0LmxvY2FsZG9tYWluMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAuKFLaf2iII/xDR+m2Yj6PnUEa+qzqwxsdLUjnunFZaAXG+hZm4Ml80SCiBgI
gTHQlJyLIkTtuRoH5aeMyz1ERUCtii4ZsTqDrjjUybxP4r+4HVX6m34s6hwEr8Fi
fts9pMp4iS3tQguRc28gPdDo/T6VrJTVYUfUUsNDRtIrlB5O9igqqLnuaY9eqGi4
PUx0G0wRYJpRywoj8G0IkpfQTiX+CAC7dt5ws7ZrnGqCNBLGi5bGsaMmptVbsSEp
1TenntF54V1iR49IV5JqDhm1S0HmkleoJzKdc+6sP/xNepz9PJzuF9d9NubTLWgB
sK28YItcmWHdHXD/ODxVaehRjwIDAQABoyAwHjAOBgNVHQ8BAf8EBAMCB4AwDAYD
VR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAAVU6sNBdj76saHwOxGSdnEqQ
o2tMuR3msSM4F6wFK2UkKepsD7CYIf/PzNSNUqA5JIEUVeMqGyiHuAbU4C655nT1
IyJX1D/+r73sSp5jbIpQm2xoQGZnj6g/Kltw8OSOAw+DsMF/PLVqoWJp07u6ew/m
NxWsJKcZ5k+q4eMxci9mKRHHqsquWKXzQlURMNFI+mGaFwrKM4dmzaR0BEc+ilSx
QqUvQ74smsLK+zhNikmgjlGC5ob9g8XkhVAkJMAh2rb9onDNiRl68iAgczP88mXu
vN/o98dypzsPxXmw6tkDqIRPUAUbh465rlY5sKMmRgXi2rUfl/QV5nbozUo/HQ==
-----END CERTIFICATE-----`

const SigningKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuKFLaf2iII/xDR+m2Yj6PnUEa+qzqwxsdLUjnunFZaAXG+hZ
m4Ml80SCiBgIgTHQlJyLIkTtuRoH5aeMyz1ERUCtii4ZsTqDrjjUybxP4r+4HVX6
m34s6hwEr8Fifts9pMp4iS3tQguRc28gPdDo/T6VrJTVYUfUUsNDRtIrlB5O9igq
qLnuaY9eqGi4PUx0G0wRYJpRywoj8G0IkpfQTiX+CAC7dt5ws7ZrnGqCNBLGi5bG
saMmptVbsSEp1TenntF54V1iR49IV5JqDhm1S0HmkleoJzKdc+6sP/xNepz9PJzu
F9d9NubTLWgBsK28YItcmWHdHXD/ODxVaehRjwIDAQABAoIBABy4orWrShRMsA/9
k4QVpfAfXf+3tBlwxlJld1QaQ6XqgI3L2FyzyyyLxM6NBo2qhSsJKy+6j0yTOxVD
ukhHkJ5BUH3FbCPA2Yk5uAhl7ft1HZwaqvCTcUM99pCswbjAPFetU5DrfxQeHpNZ
fyd+ny/+E2SUhpkqhmIVlBqpSTQyOywbiEvZ6ZiFmncdHhXaCy3YZsylrKUGPzsJ
jfU2iOE167eTOIjPStsaoCPv9jLSyy2OvuNNudS+Y1qkFz8ZGvPp+HB+Iig+AlAE
7KMzNrIW7PlHTDgUly1cRCl3+84yE2mJ97+hHiEy//HIwVDUpI529i2hMYM/u4qz
Wso/2tkCgYEA2FdE4bmCrZiA9eS8qobwGLE1+MJME4YwfJkynZUHHX93xORPQ66e
WYpN7/xbMvBDa8LZZYVTNVtZ/SkEUaTb5NQW2zXKoIutk1PFBb8NbA0m8Ss/mOJA
d5nUYGr987O9fRh1yP9TksBshHB/5A8U2UG8MFFCNvJTZDPRkuSlMiUCgYEA2nnb
hAJrhY7PaF6jdfimGvvponkUiEbWLppg7/SjgPg+QgqIwuLybryXyOAp+TEnNzgU
ujAjhNtIiyB/B13TDxOgUgWUWPbPvUAWGEvwI9h+RLie1umGHd48G1NR76fwqSf1
y7z3YRnq8vCdz8ywB3o5GO6SH6QkMJBIxfIMlKMCgYA55akOi7oYQT8KD4waSwCI
ayyZhU4cz4W8Yrd0CsUbtNhVvhAked/w8J2JA01Y5Yn1lfDeRX8OQYNkyAxa2Tbs
F4KCafPvYVIzonCQ6B9sclygoEVl4e8E0wtOPnP2O30TtG8ZOpOgK5UfIIhpfUvE
FN6LQ8PntpRwtZl5qW04bQKBgGnHhFxHG64fthZPdA9jY3E/NSCgRSuyOHN59aNY
rG1+RA6PsSXC4iRxlYAB4PCxNs6KjaaUNi5WSaprAnYbnFv5Ya802l20qmJ0C/6Z
jdydLo2xYd6mVHRTrICCd/J0OpZ8LYsGpDPUa6hSjeYVscj9CXYj1IYTYB5PTZzh
k+vHAoGBAJyA+RtBF5m64/TqhZFcesTtnpWaRhQ50xXnNVF3W1eKGPtdTDKOaENA
LJxgC1GdoEz2ilXW802H9QrdKf9GPqxwi2TVzfO6pzWkdZcmbItu+QCCFz+co+r8
+ki49FmlfbR5YVPN+8X40aLQB4xDkCHwRwTkrigzWQhIOv8NAhDA
-----END RSA PRIVATE KEY-----`

const EncryptionCertPEM = `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUDpXWZ8npv3sWeCQbB1WCwMoDe9QwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTAyMTgyMTUyNTVaFw0yMjAy
MTgyMTUyNTVaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDiEvFfAwgR8rfFPXVkJiWQGisFQNpQ5oq4ng5sD/3p
hPBBzwx0TTn+V+XG5pBTlyVe0h9kLqZ3Dnavdk9VDC1DIrc0CSKUhP01JdV9TlC/
tCek9a2IQEjEZ0pZPbU/gtXxEGyrs9JVFf0K8saMH6xB8jJwB4Eq9jB8rsWZJh4H
eyX1VEdruPdwRkFjuNhBnIax//DQSZepAhtM+mtxP+cHtRzXPlXHTpYvxcP2LoXj
SdCh/XEu8Ai33O4Ek14HIFmNQ63pmzmxhpcPm8ejDFchOEU67zeOz2RQNAefeHRg
G1gvFIcgmVXcLM+VmC0JlzNuyMFY1XUygm1PYcFz93p4OGJBkYgKifNHPcMzTLQt
PoY397WREd/kkMtvgxSDs6GQr2VwByHoo5IoQJ/OpridaDduL9NSc6YHEEXxSceM
SdI+txuZvOAJJuLR1DQ5S5xjdHBj8uDsAnmX7oORVadEJ38Aj1UlM+Lk6qnmoBEG
AXEfa3Fxyz0qgN9MrtutJO0S4BLqqmXgM9Kulp0B7e7gkRaAyNt/Y0+dAuzYva+u
Td7Qm96EEYCTwd9LM4OghTLpDCXFm5EQI+D0zEyOGhDqwQDdx3MHJoPd6xg72Zko
iADY235D/av/ZisF7acPucLvQ41gbWphQgsRTN81lRll/Wgd4EknznXq060RQBkN
bwIDAQABo1MwUTAdBgNVHQ4EFgQUzpwOh72T7DyvsvkVV9Cu4YRKBTYwHwYDVR0j
BBgwFoAUzpwOh72T7DyvsvkVV9Cu4YRKBTYwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEADSc0AEFgMcwArn9zvppOdMlF4GqyJa7mzeVAKHRyXiLm
4TSUk8oBk8GgO9f32B5sEUVBnL5FnzEUm7hMAG5DUcMXANkHguIwoISpAZdFh1Vh
H+13HIOmxre/UN9a1l829g1dANvYWcoGJc4uUtj3HF5UKcfEmrUwISimW0Mpuin+
jDlRiLvpvImqxWUyFazucpE8Kj4jqmFNnoOLAQbEerR61W1wC3fpifM9cW5mKLsS
pk9uG5PUTWKA1W7u+8AgLxvfdbFA9HnDc93JKWeWyBLX6GSeVL6y9pOY9MRBHqnp
PVEPcjbZ3ZpX1EPWbniF+WRCIpjcye0obTTjipWJli5HqwGGauyXPGmevCkG96ji
y8nf18HrQ3459SuRSZ1lQD5EoF+1QBL/O1Y6P7PVuOSQev376RD56tOLu1EWxZAm
fDNNmlZSmZSn+h5JRcjSh1NFfktIVkHtNPKw8FXDp8098oqrJ3MoNTQgE0vpXiho
1QIxWhfaEU5y/WynZFk1PssjBULWNxbeIpOFYk3paNyEpb9cOkOE8ZHOdi7WWJSw
HaDmx6qizOQXO75QMLIMxkCdENFx6wWbNMvKCxOlPfgkNcBaAsybM+K0AHwwvyzl
cpVfEdaCexGtecBoGkjFRCG+f9InppaaSzmgbIJvkSOMUWEDO/JlFizzWAG8koM=
-----END CERTIFICATE-----`

const EncryptionKeyPEM = `-----BEGIN PRIVATE KEY-----
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
T+zhBIl1qramlEnT1hYCydxx4ceziIo=
-----END PRIVATE KEY-----`

// UUID is the unique identifier used in tests
const UUID = "11111111-1111-1111-1111-111111111111"

// UserCertificateRolesAndTraits is a SSH user certificate in the standard
// format with roles "admin" and traits "logins": []string{"foo"}.
const UserCertificateStandard = `ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgeB1flZgJfeV7s+K3bgQA0cSQ4y+YttYjvdAehNV+cIAAAAADAQABAAABAQDH76SMYg80Iyd3+E80R7tr4BwUEcAwXNpNzp8DNfI/pxl7bl85mkCj0JU2CD+ANLWjFtJcbPP7QLkb/IT7HJhjt+bVeHrqgCs8ImK0fu8lbHEu8rAaJTyopQlDkrBLoIMUcoDB4Ox/A4Oo/LfdDr2JJYlZfhav6lIT1u0w5ZKldl4FGlODlnuS3QE8ljVHseiUEfE/Jvb/uMaYyGFdrU3lozX41eUK0AREcriCgkO4Y9GBGB0BqZjJsjYIMoGu6NIRuEDzhC562r33mzCGdVxBBVJnhf5u0faAZrO0thZRUXUEzJ3+nbXR8TMZeAuA8XmCsqgBAEGGtyu13Rwxx1AhAAAAAAAAAAAAAAABAAAAA2ZvbwAAAAcAAAADZm9vAAAAAF1CHPgAAAAAXUIdcAAAAAAAAAB5AAAACnBlcm1pdC1wdHkAAAAAAAAADnRlbGVwb3J0LXJvbGVzAAAAJgAAACJ7InZlcnNpb24iOiJ2MSIsInJvbGVzIjpbImFkbWluIl19AAAAD3RlbGVwb3J0LXRyYWl0cwAAABQAAAAQCg4KBWxvZ2luEgUKA2ZvbwAAAAAAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQC018WJxQ6S117eabPMCLpZ5AgdI9tMXe4bYdHReMJ5mqqnoaCynrjFAowa2bXmifIBWso5NA1JVnbXWX2kcSObcLdG1iwjutak9bWrvBukncz8KO/4p+D/8fIXDNtpbqao0tOxriS7Ez2bHzq0DM0H0VgEZK/NCtxGC4FdH1nrwhanI0S7+GUUSZidkN2LaN9Nbn5DjdbvbkeG+L1DvIdKaEOrHV888GhtLkU4oBEe0w7t8WBbK2Ly5GCP3LoAyppHAY6pXca94bEFfRZG6PFY/H7hViXUg4R+08ByNy64+6aX1zHP4LcgMxb09bz22X9v88a8Dg4c504hGZ3lYEvNAAABDwAAAAdzc2gtcnNhAAABAC0T0ZuIyY8jJRSvKAJGyoJDX0oM6ZCM92ebBelZFo8hGU2K9l6DdGUJ8Jsm+asinWSe5eUAxAULsRvNZRbaw8ADAdvuzDAeUXTmwDUWOEFYVskH9bTratTYKACXFh4bLmDxYko3Kc5Iqf7irtvIyoOhNqyY6ODS4kNU8O6moChA7kXvKITkJuYHoHdk/8nDuU42Im72hYMmO1E+LQqmEtX9khE9OGjrdhLPeti4+mUo0vlEpLb271Ex3KNz2Nrnq/4UCC/GRxY7bhW2Qhmb6PLK7qlrdP+3K2flAnEiirCHvLUO4HipaQa/c13IsidXknHLwmdgwU3cG26eNafcVwc=`

// UserCertificateLegacy is a SSH user certificate in the old legacy format.
const UserCertificateLegacy = `ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgUTR740WMqrewurgb80LEYI4ePvOoDSS1PuG/fVOtd+UAAAADAQABAAABAQC4gxu87n0GfSqgTrcbDByLmWl2cpvJqHSfHtYTenfhfKoXyYqnVT6YMHSov13gT0l3RMVy/qFKJfbRREGjSQ/YW1zG/y0xCnjRmKgPLyHLzyc+yOrTbIwn9rHIJeuF1DlIJLzhUo/MMi4UZPHLtsLBiJ94MVQMj3R2fRC55gm0ZKcvpmk3H57wbbEze4gQLXI2Crl/JxG0h9CSV5YfRbvftbpoTOR9A4tYQUvNobBz8scdAGHpOYilBIkANwzwOmNw/CLikD6TtirWzwCq/GiO0oec5oeb2Anrq7uGHYzZzx+E+iNe+ebY/xiuN8anLYa9JGQ4YlLSC47xOM+8LviTAAAAAAAAAAAAAAABAAAAA2ZvbwAAAAcAAAADZm9vAAAAAF1CHqcAAAAAXUIfHwAAAAAAAAASAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAOrxHaRQxJKiZ/XZJMs+p4H8bai3aPVgavGIE9uB+1LGkGNzWy1QWmePLBcFred5aNnpoTjl3ZPRT5iRfnaK0ggl8P/4k1O+ZtUkDTDcbtVyjCH9raVzqOtQ/BEu5sXEokOHNRuySJSMJLUQZV94vGpIuXmRY6z8X4uwI4ui/ZUFLOLCcilWxxg87dKnUm9Tg1TzTDHE5M9QXCrUl/IOoV2491paoiUJRvFSQMCQfTCePrBcKne+f5S2gmV8KIMaL4ucFFMhxcP5rVPd/bNDquM46MW9TrESzl6XETKrOO5psgHWKUgCM44u+DOjvbqUOAWc6IIDQ7KonxToTSTehqcAAAEPAAAAB3NzaC1yc2EAAAEArj9BOUTTbPhv6MahtMa/oe9mnZI/R0c5kTtDplGFbfNSg2JI6UHbE/ijM4yR3X2f4tuj4eL4MJxFYKik+mJ7fhxuxlsYq42CILr/7uDu4YKLwdS5pYZtyIVF2KeYjdMZrdXBo/c1dfNgiAvQCyY4knjxnRNgGG7pRw1R2qDQjXlxqrdFiPLgLKAkY/gcBDio4iIlfe/bqNnlJTHDQ4+E8v1PQw1zHJ65WADd8iMT6+RyJ2B9h6B1b2Mtj17pf8DOT6snjmq/FUgYgN1n6wh8IuMMGOOF5orOWjYeXrqQeN1kNN95eQrSXsGEesDJgMeL2Km3KZOH1+ZTGnvoierzlA==`
