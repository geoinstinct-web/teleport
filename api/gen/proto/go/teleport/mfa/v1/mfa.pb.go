// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: teleport/mfa/v1/mfa.proto

package mfav1

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// ChallengeScope is a scope authorized by an MFA challenge resolution.
type ChallengeScope int32

const (
	// Scope unknown or not specified.
	ChallengeScope_CHALLENGE_SCOPE_UNSPECIFIED ChallengeScope = 0
	// Standard webauthn login.
	ChallengeScope_CHALLENGE_SCOPE_LOGIN ChallengeScope = 1
	// Passwordless webauthn login.
	ChallengeScope_CHALLENGE_SCOPE_PASSWORDLESS_LOGIN ChallengeScope = 2
	// Headless login.
	ChallengeScope_CHALLENGE_SCOPE_HEADLESS_LOGIN ChallengeScope = 3
	// MFA device management.
	ChallengeScope_CHALLENGE_SCOPE_MANAGE_DEVICES ChallengeScope = 4
	// Account recovery.
	ChallengeScope_CHALLENGE_SCOPE_ACCOUNT_RECOVERY ChallengeScope = 5
	// Used for per-session MFA and moderated session presence checks.
	ChallengeScope_CHALLENGE_SCOPE_USER_SESSION ChallengeScope = 6
	// Used for various administrative actions, such as adding, updating, or
	// deleting administrative resources (users, roles, etc.).
	//
	// Note: this scope should not be used for new MFA capabilities that have
	// more precise scope. Instead, new scopes should be added. This scope may
	// also be split into multiple smaller scopes in the future.
	ChallengeScope_CHALLENGE_SCOPE_ADMIN_ACTION ChallengeScope = 7
)

var ChallengeScope_name = map[int32]string{
	0: "CHALLENGE_SCOPE_UNSPECIFIED",
	1: "CHALLENGE_SCOPE_LOGIN",
	2: "CHALLENGE_SCOPE_PASSWORDLESS_LOGIN",
	3: "CHALLENGE_SCOPE_HEADLESS_LOGIN",
	4: "CHALLENGE_SCOPE_MANAGE_DEVICES",
	5: "CHALLENGE_SCOPE_ACCOUNT_RECOVERY",
	6: "CHALLENGE_SCOPE_USER_SESSION",
	7: "CHALLENGE_SCOPE_ADMIN_ACTION",
}

var ChallengeScope_value = map[string]int32{
	"CHALLENGE_SCOPE_UNSPECIFIED":        0,
	"CHALLENGE_SCOPE_LOGIN":              1,
	"CHALLENGE_SCOPE_PASSWORDLESS_LOGIN": 2,
	"CHALLENGE_SCOPE_HEADLESS_LOGIN":     3,
	"CHALLENGE_SCOPE_MANAGE_DEVICES":     4,
	"CHALLENGE_SCOPE_ACCOUNT_RECOVERY":   5,
	"CHALLENGE_SCOPE_USER_SESSION":       6,
	"CHALLENGE_SCOPE_ADMIN_ACTION":       7,
}

func (x ChallengeScope) String() string {
	return proto.EnumName(ChallengeScope_name, int32(x))
}

func (ChallengeScope) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_eb9e544d66a5853a, []int{0}
}

// ChallengeAllowReuse determines whether an MFA challenge response can be used
// to authenticate the user more than once until the challenge expires.
//
// Reuse is only permitted for specific actions by the discretion of the server.
// See the server implementation for details.
type ChallengeAllowReuse int32

const (
	// Reuse unspecified, treated as CHALLENGE_ALLOW_REUSE_NO.
	ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_UNSPECIFIED ChallengeAllowReuse = 0
	// Reuse is permitted.
	ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES ChallengeAllowReuse = 1
	// Reuse is not permitted.
	ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO ChallengeAllowReuse = 2
)

var ChallengeAllowReuse_name = map[int32]string{
	0: "CHALLENGE_ALLOW_REUSE_UNSPECIFIED",
	1: "CHALLENGE_ALLOW_REUSE_YES",
	2: "CHALLENGE_ALLOW_REUSE_NO",
}

var ChallengeAllowReuse_value = map[string]int32{
	"CHALLENGE_ALLOW_REUSE_UNSPECIFIED": 0,
	"CHALLENGE_ALLOW_REUSE_YES":         1,
	"CHALLENGE_ALLOW_REUSE_NO":          2,
}

func (x ChallengeAllowReuse) String() string {
	return proto.EnumName(ChallengeAllowReuse_name, int32(x))
}

func (ChallengeAllowReuse) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_eb9e544d66a5853a, []int{1}
}

// User verification requirement for the challenge.
// See https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement.
type UserVerificationRequirement int32

const (
	// User verification requirement not specified.
	// Functionally equivalent to VERIFICATION_REQUIREMENT_DISCOURAGED.
	UserVerificationRequirement_USER_VERIFICATION_REQUIREMENT_UNSPECIFIED UserVerificationRequirement = 0
	// User verification required.
	// The server will reject challenge responses with UV=0.
	UserVerificationRequirement_USER_VERIFICATION_REQUIREMENT_REQUIRED UserVerificationRequirement = 1
	// User verification is desirable but not mandatory.
	// The server will accept challenge responses with any UV value.
	UserVerificationRequirement_USER_VERIFICATION_REQUIREMENT_PREFERRED UserVerificationRequirement = 2
	// User verification actively discouraged.
	// The server will accept challenge responses with any UV value.
	UserVerificationRequirement_USER_VERIFICATION_REQUIREMENT_DISCOURAGED UserVerificationRequirement = 3
)

var UserVerificationRequirement_name = map[int32]string{
	0: "USER_VERIFICATION_REQUIREMENT_UNSPECIFIED",
	1: "USER_VERIFICATION_REQUIREMENT_REQUIRED",
	2: "USER_VERIFICATION_REQUIREMENT_PREFERRED",
	3: "USER_VERIFICATION_REQUIREMENT_DISCOURAGED",
}

var UserVerificationRequirement_value = map[string]int32{
	"USER_VERIFICATION_REQUIREMENT_UNSPECIFIED": 0,
	"USER_VERIFICATION_REQUIREMENT_REQUIRED":    1,
	"USER_VERIFICATION_REQUIREMENT_PREFERRED":   2,
	"USER_VERIFICATION_REQUIREMENT_DISCOURAGED": 3,
}

func (x UserVerificationRequirement) String() string {
	return proto.EnumName(UserVerificationRequirement_name, int32(x))
}

func (UserVerificationRequirement) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_eb9e544d66a5853a, []int{2}
}

// ChallengeExtensions contains MFA challenge extensions used by Teleport
// during MFA authentication.
type ChallengeExtensions struct {
	// Scope is an authorization scope for this MFA challenge.
	// Required.
	Scope ChallengeScope `protobuf:"varint,1,opt,name=scope,proto3,enum=teleport.mfa.v1.ChallengeScope" json:"scope,omitempty"`
	// AllowReuse determines whether the MFA challenge allows reuse.
	// Defaults to CHALLENGE_ALLOW_REUSE_NO.
	//
	// Note that reuse is only permitted for specific actions by the discretion
	// of the server. See the server implementation for details.
	AllowReuse ChallengeAllowReuse `protobuf:"varint,2,opt,name=allow_reuse,json=allowReuse,proto3,enum=teleport.mfa.v1.ChallengeAllowReuse" json:"allow_reuse,omitempty"`
	// User verification requirement for the challenge.
	// Optional.
	UserVerificationRequirement UserVerificationRequirement `protobuf:"varint,3,opt,name=user_verification_requirement,json=userVerificationRequirement,proto3,enum=teleport.mfa.v1.UserVerificationRequirement" json:"user_verification_requirement,omitempty"`
	XXX_NoUnkeyedLiteral        struct{}                    `json:"-"`
	XXX_unrecognized            []byte                      `json:"-"`
	XXX_sizecache               int32                       `json:"-"`
}

func (m *ChallengeExtensions) Reset()         { *m = ChallengeExtensions{} }
func (m *ChallengeExtensions) String() string { return proto.CompactTextString(m) }
func (*ChallengeExtensions) ProtoMessage()    {}
func (*ChallengeExtensions) Descriptor() ([]byte, []int) {
	return fileDescriptor_eb9e544d66a5853a, []int{0}
}
func (m *ChallengeExtensions) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ChallengeExtensions) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ChallengeExtensions.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ChallengeExtensions) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ChallengeExtensions.Merge(m, src)
}
func (m *ChallengeExtensions) XXX_Size() int {
	return m.Size()
}
func (m *ChallengeExtensions) XXX_DiscardUnknown() {
	xxx_messageInfo_ChallengeExtensions.DiscardUnknown(m)
}

var xxx_messageInfo_ChallengeExtensions proto.InternalMessageInfo

func (m *ChallengeExtensions) GetScope() ChallengeScope {
	if m != nil {
		return m.Scope
	}
	return ChallengeScope_CHALLENGE_SCOPE_UNSPECIFIED
}

func (m *ChallengeExtensions) GetAllowReuse() ChallengeAllowReuse {
	if m != nil {
		return m.AllowReuse
	}
	return ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_UNSPECIFIED
}

func (m *ChallengeExtensions) GetUserVerificationRequirement() UserVerificationRequirement {
	if m != nil {
		return m.UserVerificationRequirement
	}
	return UserVerificationRequirement_USER_VERIFICATION_REQUIREMENT_UNSPECIFIED
}

func init() {
	proto.RegisterEnum("teleport.mfa.v1.ChallengeScope", ChallengeScope_name, ChallengeScope_value)
	proto.RegisterEnum("teleport.mfa.v1.ChallengeAllowReuse", ChallengeAllowReuse_name, ChallengeAllowReuse_value)
	proto.RegisterEnum("teleport.mfa.v1.UserVerificationRequirement", UserVerificationRequirement_name, UserVerificationRequirement_value)
	proto.RegisterType((*ChallengeExtensions)(nil), "teleport.mfa.v1.ChallengeExtensions")
}

func init() { proto.RegisterFile("teleport/mfa/v1/mfa.proto", fileDescriptor_eb9e544d66a5853a) }

var fileDescriptor_eb9e544d66a5853a = []byte{
	// 533 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x94, 0xc1, 0x6e, 0xd3, 0x4c,
	0x14, 0x85, 0x7f, 0xbb, 0x7f, 0x8b, 0x34, 0x48, 0xc5, 0x1a, 0x40, 0x4a, 0x48, 0x9b, 0x86, 0xa8,
	0x14, 0x08, 0x10, 0x2b, 0x20, 0x56, 0xac, 0x06, 0xfb, 0x26, 0xb1, 0xe4, 0xd8, 0x61, 0x26, 0x4e,
	0x55, 0x36, 0x23, 0x37, 0x9a, 0xb8, 0x96, 0x1c, 0x3b, 0xd8, 0x4e, 0x80, 0x07, 0xe0, 0x55, 0x78,
	0x16, 0x96, 0x2c, 0x78, 0x00, 0x94, 0x27, 0x41, 0x76, 0xdb, 0x24, 0xb8, 0x69, 0x58, 0xf9, 0xca,
	0xe7, 0x3b, 0x57, 0xf7, 0x78, 0x7c, 0x07, 0x95, 0x53, 0x11, 0x88, 0x69, 0x14, 0xa7, 0xea, 0x64,
	0xec, 0xaa, 0xf3, 0x56, 0xf6, 0x68, 0x4e, 0xe3, 0x28, 0x8d, 0xf0, 0xbd, 0x6b, 0xa9, 0x99, 0xbd,
	0x9b, 0xb7, 0x1e, 0x3d, 0xf0, 0x22, 0x2f, 0xca, 0x35, 0x35, 0xab, 0x2e, 0xb1, 0xfa, 0x37, 0x19,
	0xdd, 0xd7, 0x2e, 0xdc, 0x20, 0x10, 0xa1, 0x27, 0xe0, 0x4b, 0x2a, 0xc2, 0xc4, 0x8f, 0xc2, 0x04,
	0xbf, 0x45, 0xbb, 0xc9, 0x28, 0x9a, 0x8a, 0x92, 0x54, 0x93, 0x9e, 0xed, 0xbf, 0x3e, 0x6a, 0x16,
	0xda, 0x35, 0x97, 0x26, 0x96, 0x61, 0xf4, 0x92, 0xc6, 0x80, 0xee, 0xba, 0x41, 0x10, 0x7d, 0xe6,
	0xb1, 0x98, 0x25, 0xa2, 0x24, 0xe7, 0xe6, 0xe3, 0xdb, 0xcd, 0x24, 0x83, 0x69, 0xc6, 0x52, 0xe4,
	0x2e, 0x6b, 0x3c, 0x45, 0x87, 0xb3, 0x44, 0xc4, 0x7c, 0x2e, 0x62, 0x7f, 0xec, 0x8f, 0xdc, 0xd4,
	0x8f, 0x42, 0x1e, 0x8b, 0x4f, 0x33, 0x3f, 0x16, 0x13, 0x11, 0xa6, 0xa5, 0x9d, 0xbc, 0xf1, 0xcb,
	0x1b, 0x8d, 0x9d, 0x44, 0xc4, 0xc3, 0x35, 0x13, 0x5d, 0x79, 0x68, 0x65, 0x76, 0xbb, 0xd8, 0xf8,
	0x2e, 0xa3, 0xfd, 0xbf, 0x23, 0xe1, 0x23, 0x54, 0xd1, 0xba, 0xc4, 0x34, 0xc1, 0xea, 0x00, 0x67,
	0x9a, 0xdd, 0x07, 0xee, 0x58, 0xac, 0x0f, 0x9a, 0xd1, 0x36, 0x40, 0x57, 0xfe, 0xc3, 0x65, 0xf4,
	0xb0, 0x08, 0x98, 0x76, 0xc7, 0xb0, 0x14, 0x09, 0x9f, 0xa0, 0x7a, 0x51, 0xea, 0x13, 0xc6, 0x4e,
	0x6d, 0xaa, 0x9b, 0xc0, 0xd8, 0x15, 0x27, 0xe3, 0x3a, 0xaa, 0x16, 0xb9, 0x2e, 0x90, 0x75, 0x66,
	0x67, 0x13, 0xd3, 0x23, 0x16, 0xe9, 0x00, 0xd7, 0x61, 0x68, 0x68, 0xc0, 0x94, 0xff, 0xf1, 0x31,
	0xaa, 0x15, 0x19, 0xa2, 0x69, 0xb6, 0x63, 0x0d, 0x38, 0x05, 0xcd, 0x1e, 0x02, 0x3d, 0x53, 0x76,
	0x71, 0x0d, 0x1d, 0xdc, 0x48, 0xc4, 0x80, 0x72, 0x06, 0x8c, 0x19, 0xb6, 0xa5, 0xec, 0x6d, 0x22,
	0x88, 0xde, 0x33, 0x2c, 0x4e, 0xb4, 0x41, 0x46, 0xdc, 0x69, 0x7c, 0x5d, 0xfb, 0x5f, 0x56, 0xa7,
	0x87, 0x9f, 0xa0, 0xc7, 0x2b, 0x23, 0x31, 0x4d, 0xfb, 0x94, 0x53, 0x70, 0x58, 0xf1, 0x93, 0x1d,
	0xa2, 0xf2, 0x66, 0xec, 0x0c, 0x98, 0x22, 0xe1, 0x03, 0x54, 0xda, 0x2c, 0x5b, 0xb6, 0x22, 0x37,
	0x7e, 0x49, 0xa8, 0xb2, 0xe5, 0x80, 0xf1, 0x2b, 0xf4, 0x3c, 0x8f, 0x33, 0x04, 0x6a, 0xb4, 0x0d,
	0x8d, 0x64, 0x13, 0x73, 0x0a, 0x1f, 0x1c, 0x83, 0x42, 0x0f, 0xac, 0x41, 0x61, 0x96, 0x06, 0x3a,
	0xd9, 0x8e, 0x5f, 0xd5, 0xba, 0x22, 0xe1, 0x17, 0xe8, 0xe9, 0x76, 0xb6, 0x4f, 0xa1, 0x0d, 0x34,
	0x83, 0xe5, 0x7f, 0xcf, 0xa1, 0x1b, 0x4c, 0xb3, 0x1d, 0x4a, 0x3a, 0xa0, 0x2b, 0x3b, 0xef, 0x87,
	0x3f, 0x16, 0x55, 0xe9, 0xe7, 0xa2, 0x2a, 0xfd, 0x5e, 0x54, 0xa5, 0x8f, 0x5d, 0xcf, 0x4f, 0x2f,
	0x66, 0xe7, 0xcd, 0x51, 0x34, 0x51, 0xbd, 0xd8, 0x9d, 0xfb, 0x69, 0x9e, 0xd3, 0x0d, 0xd4, 0xe5,
	0xae, 0xbb, 0x53, 0x5f, 0xf5, 0x44, 0xa8, 0x5e, 0x2f, 0xb3, 0x5a, 0xb8, 0x05, 0xde, 0x4d, 0xc6,
	0xee, 0xbc, 0x75, 0xbe, 0x97, 0xeb, 0x6f, 0xfe, 0x04, 0x00, 0x00, 0xff, 0xff, 0xda, 0xe6, 0xe7,
	0x0e, 0x25, 0x04, 0x00, 0x00,
}

func (m *ChallengeExtensions) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ChallengeExtensions) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ChallengeExtensions) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.UserVerificationRequirement != 0 {
		i = encodeVarintMfa(dAtA, i, uint64(m.UserVerificationRequirement))
		i--
		dAtA[i] = 0x18
	}
	if m.AllowReuse != 0 {
		i = encodeVarintMfa(dAtA, i, uint64(m.AllowReuse))
		i--
		dAtA[i] = 0x10
	}
	if m.Scope != 0 {
		i = encodeVarintMfa(dAtA, i, uint64(m.Scope))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintMfa(dAtA []byte, offset int, v uint64) int {
	offset -= sovMfa(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *ChallengeExtensions) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Scope != 0 {
		n += 1 + sovMfa(uint64(m.Scope))
	}
	if m.AllowReuse != 0 {
		n += 1 + sovMfa(uint64(m.AllowReuse))
	}
	if m.UserVerificationRequirement != 0 {
		n += 1 + sovMfa(uint64(m.UserVerificationRequirement))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovMfa(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMfa(x uint64) (n int) {
	return sovMfa(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ChallengeExtensions) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMfa
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ChallengeExtensions: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ChallengeExtensions: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Scope", wireType)
			}
			m.Scope = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMfa
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Scope |= ChallengeScope(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field AllowReuse", wireType)
			}
			m.AllowReuse = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMfa
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.AllowReuse |= ChallengeAllowReuse(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field UserVerificationRequirement", wireType)
			}
			m.UserVerificationRequirement = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMfa
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.UserVerificationRequirement |= UserVerificationRequirement(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipMfa(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMfa
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipMfa(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMfa
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMfa
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMfa
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthMfa
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMfa
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMfa
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMfa        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMfa          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMfa = fmt.Errorf("proto: unexpected end of group")
)
