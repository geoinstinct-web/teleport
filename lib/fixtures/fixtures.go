package fixtures

import (
	"runtime/debug"

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

// DeepCompare uses gocheck DeepEquals but provides nice diff if things are not equal
func DeepCompare(c *check.C, a, b interface{}) {
	d := &spew.ConfigState{Indent: " ", DisableMethods: true, DisablePointerMethods: true, DisablePointerAddresses: true}

	c.Assert(a, check.DeepEquals, b, check.Commentf("%v\nStack:\n%v\n", diff.Diff(d.Sdump(a), d.Sdump(b)), string(debug.Stack())))
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

// UUID is the unique identifier used in tests
const UUID = "11111111-1111-1111-1111-111111111111"

// UserCertificateRolesAndTraits is a SSH user certificate in the standard
// format with roles "admin" and traits "logins": []string{"foo"}.
const UserCertificateStandard = `ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgeB1flZgJfeV7s+K3bgQA0cSQ4y+YttYjvdAehNV+cIAAAAADAQABAAABAQDH76SMYg80Iyd3+E80R7tr4BwUEcAwXNpNzp8DNfI/pxl7bl85mkCj0JU2CD+ANLWjFtJcbPP7QLkb/IT7HJhjt+bVeHrqgCs8ImK0fu8lbHEu8rAaJTyopQlDkrBLoIMUcoDB4Ox/A4Oo/LfdDr2JJYlZfhav6lIT1u0w5ZKldl4FGlODlnuS3QE8ljVHseiUEfE/Jvb/uMaYyGFdrU3lozX41eUK0AREcriCgkO4Y9GBGB0BqZjJsjYIMoGu6NIRuEDzhC562r33mzCGdVxBBVJnhf5u0faAZrO0thZRUXUEzJ3+nbXR8TMZeAuA8XmCsqgBAEGGtyu13Rwxx1AhAAAAAAAAAAAAAAABAAAAA2ZvbwAAAAcAAAADZm9vAAAAAF1CHPgAAAAAXUIdcAAAAAAAAAB5AAAACnBlcm1pdC1wdHkAAAAAAAAADnRlbGVwb3J0LXJvbGVzAAAAJgAAACJ7InZlcnNpb24iOiJ2MSIsInJvbGVzIjpbImFkbWluIl19AAAAD3RlbGVwb3J0LXRyYWl0cwAAABQAAAAQCg4KBWxvZ2luEgUKA2ZvbwAAAAAAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQC018WJxQ6S117eabPMCLpZ5AgdI9tMXe4bYdHReMJ5mqqnoaCynrjFAowa2bXmifIBWso5NA1JVnbXWX2kcSObcLdG1iwjutak9bWrvBukncz8KO/4p+D/8fIXDNtpbqao0tOxriS7Ez2bHzq0DM0H0VgEZK/NCtxGC4FdH1nrwhanI0S7+GUUSZidkN2LaN9Nbn5DjdbvbkeG+L1DvIdKaEOrHV888GhtLkU4oBEe0w7t8WBbK2Ly5GCP3LoAyppHAY6pXca94bEFfRZG6PFY/H7hViXUg4R+08ByNy64+6aX1zHP4LcgMxb09bz22X9v88a8Dg4c504hGZ3lYEvNAAABDwAAAAdzc2gtcnNhAAABAC0T0ZuIyY8jJRSvKAJGyoJDX0oM6ZCM92ebBelZFo8hGU2K9l6DdGUJ8Jsm+asinWSe5eUAxAULsRvNZRbaw8ADAdvuzDAeUXTmwDUWOEFYVskH9bTratTYKACXFh4bLmDxYko3Kc5Iqf7irtvIyoOhNqyY6ODS4kNU8O6moChA7kXvKITkJuYHoHdk/8nDuU42Im72hYMmO1E+LQqmEtX9khE9OGjrdhLPeti4+mUo0vlEpLb271Ex3KNz2Nrnq/4UCC/GRxY7bhW2Qhmb6PLK7qlrdP+3K2flAnEiirCHvLUO4HipaQa/c13IsidXknHLwmdgwU3cG26eNafcVwc=`

// UserCertificateLegacy is a SSH user certificate in the old legacy format.
const UserCertificateLegacy = `ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgUTR740WMqrewurgb80LEYI4ePvOoDSS1PuG/fVOtd+UAAAADAQABAAABAQC4gxu87n0GfSqgTrcbDByLmWl2cpvJqHSfHtYTenfhfKoXyYqnVT6YMHSov13gT0l3RMVy/qFKJfbRREGjSQ/YW1zG/y0xCnjRmKgPLyHLzyc+yOrTbIwn9rHIJeuF1DlIJLzhUo/MMi4UZPHLtsLBiJ94MVQMj3R2fRC55gm0ZKcvpmk3H57wbbEze4gQLXI2Crl/JxG0h9CSV5YfRbvftbpoTOR9A4tYQUvNobBz8scdAGHpOYilBIkANwzwOmNw/CLikD6TtirWzwCq/GiO0oec5oeb2Anrq7uGHYzZzx+E+iNe+ebY/xiuN8anLYa9JGQ4YlLSC47xOM+8LviTAAAAAAAAAAAAAAABAAAAA2ZvbwAAAAcAAAADZm9vAAAAAF1CHqcAAAAAXUIfHwAAAAAAAAASAAAACnBlcm1pdC1wdHkAAAAAAAAAAAAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAOrxHaRQxJKiZ/XZJMs+p4H8bai3aPVgavGIE9uB+1LGkGNzWy1QWmePLBcFred5aNnpoTjl3ZPRT5iRfnaK0ggl8P/4k1O+ZtUkDTDcbtVyjCH9raVzqOtQ/BEu5sXEokOHNRuySJSMJLUQZV94vGpIuXmRY6z8X4uwI4ui/ZUFLOLCcilWxxg87dKnUm9Tg1TzTDHE5M9QXCrUl/IOoV2491paoiUJRvFSQMCQfTCePrBcKne+f5S2gmV8KIMaL4ucFFMhxcP5rVPd/bNDquM46MW9TrESzl6XETKrOO5psgHWKUgCM44u+DOjvbqUOAWc6IIDQ7KonxToTSTehqcAAAEPAAAAB3NzaC1yc2EAAAEArj9BOUTTbPhv6MahtMa/oe9mnZI/R0c5kTtDplGFbfNSg2JI6UHbE/ijM4yR3X2f4tuj4eL4MJxFYKik+mJ7fhxuxlsYq42CILr/7uDu4YKLwdS5pYZtyIVF2KeYjdMZrdXBo/c1dfNgiAvQCyY4knjxnRNgGG7pRw1R2qDQjXlxqrdFiPLgLKAkY/gcBDio4iIlfe/bqNnlJTHDQ4+E8v1PQw1zHJ65WADd8iMT6+RyJ2B9h6B1b2Mtj17pf8DOT6snjmq/FUgYgN1n6wh8IuMMGOOF5orOWjYeXrqQeN1kNN95eQrSXsGEesDJgMeL2Km3KZOH1+ZTGnvoierzlA==`
