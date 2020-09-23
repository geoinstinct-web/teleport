// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: membership.proto

/*
	Package membershippb is a generated protocol buffer package.

	It is generated from these files:
		membership.proto

	It has these top-level messages:
		RaftAttributes
		Attributes
		Member
		ClusterVersionSetRequest
		ClusterMemberAttrSetRequest
*/
package membershippb

import (
	"fmt"

	proto "github.com/golang/protobuf/proto"

	math "math"

	_ "github.com/gogo/protobuf/gogoproto"

	io "io"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// RaftAttributes represents the raft related attributes of an etcd member.
type RaftAttributes struct {
	// peerURLs is the list of peers in the raft cluster.
	PeerUrls []string `protobuf:"bytes,1,rep,name=peer_urls,json=peerUrls" json:"peer_urls,omitempty"`
	// isLearner indicates if the member is raft learner.
	IsLearner bool `protobuf:"varint,2,opt,name=is_learner,json=isLearner,proto3" json:"is_learner,omitempty"`
}

func (m *RaftAttributes) Reset()                    { *m = RaftAttributes{} }
func (m *RaftAttributes) String() string            { return proto.CompactTextString(m) }
func (*RaftAttributes) ProtoMessage()               {}
func (*RaftAttributes) Descriptor() ([]byte, []int) { return fileDescriptorMembership, []int{0} }

// Attributes represents all the non-raft related attributes of an etcd member.
type Attributes struct {
	Name       string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	ClientUrls []string `protobuf:"bytes,2,rep,name=client_urls,json=clientUrls" json:"client_urls,omitempty"`
}

func (m *Attributes) Reset()                    { *m = Attributes{} }
func (m *Attributes) String() string            { return proto.CompactTextString(m) }
func (*Attributes) ProtoMessage()               {}
func (*Attributes) Descriptor() ([]byte, []int) { return fileDescriptorMembership, []int{1} }

type Member struct {
	ID               uint64          `protobuf:"varint,1,opt,name=ID,proto3" json:"ID,omitempty"`
	RaftAttributes   *RaftAttributes `protobuf:"bytes,2,opt,name=raft_attributes,json=raftAttributes" json:"raft_attributes,omitempty"`
	MemberAttributes *Attributes     `protobuf:"bytes,3,opt,name=member_attributes,json=memberAttributes" json:"member_attributes,omitempty"`
}

func (m *Member) Reset()                    { *m = Member{} }
func (m *Member) String() string            { return proto.CompactTextString(m) }
func (*Member) ProtoMessage()               {}
func (*Member) Descriptor() ([]byte, []int) { return fileDescriptorMembership, []int{2} }

type ClusterVersionSetRequest struct {
	Ver string `protobuf:"bytes,1,opt,name=ver,proto3" json:"ver,omitempty"`
}

func (m *ClusterVersionSetRequest) Reset()         { *m = ClusterVersionSetRequest{} }
func (m *ClusterVersionSetRequest) String() string { return proto.CompactTextString(m) }
func (*ClusterVersionSetRequest) ProtoMessage()    {}
func (*ClusterVersionSetRequest) Descriptor() ([]byte, []int) {
	return fileDescriptorMembership, []int{3}
}

type ClusterMemberAttrSetRequest struct {
	Member_ID        uint64      `protobuf:"varint,1,opt,name=member_ID,json=memberID,proto3" json:"member_ID,omitempty"`
	MemberAttributes *Attributes `protobuf:"bytes,2,opt,name=member_attributes,json=memberAttributes" json:"member_attributes,omitempty"`
}

func (m *ClusterMemberAttrSetRequest) Reset()         { *m = ClusterMemberAttrSetRequest{} }
func (m *ClusterMemberAttrSetRequest) String() string { return proto.CompactTextString(m) }
func (*ClusterMemberAttrSetRequest) ProtoMessage()    {}
func (*ClusterMemberAttrSetRequest) Descriptor() ([]byte, []int) {
	return fileDescriptorMembership, []int{4}
}

func init() {
	proto.RegisterType((*RaftAttributes)(nil), "membershippb.RaftAttributes")
	proto.RegisterType((*Attributes)(nil), "membershippb.Attributes")
	proto.RegisterType((*Member)(nil), "membershippb.Member")
	proto.RegisterType((*ClusterVersionSetRequest)(nil), "membershippb.ClusterVersionSetRequest")
	proto.RegisterType((*ClusterMemberAttrSetRequest)(nil), "membershippb.ClusterMemberAttrSetRequest")
}
func (m *RaftAttributes) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *RaftAttributes) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.PeerUrls) > 0 {
		for _, s := range m.PeerUrls {
			dAtA[i] = 0xa
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
	if m.IsLearner {
		dAtA[i] = 0x10
		i++
		if m.IsLearner {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i++
	}
	return i, nil
}

func (m *Attributes) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Attributes) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintMembership(dAtA, i, uint64(len(m.Name)))
		i += copy(dAtA[i:], m.Name)
	}
	if len(m.ClientUrls) > 0 {
		for _, s := range m.ClientUrls {
			dAtA[i] = 0x12
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
	return i, nil
}

func (m *Member) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Member) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.ID != 0 {
		dAtA[i] = 0x8
		i++
		i = encodeVarintMembership(dAtA, i, uint64(m.ID))
	}
	if m.RaftAttributes != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintMembership(dAtA, i, uint64(m.RaftAttributes.Size()))
		n1, err := m.RaftAttributes.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.MemberAttributes != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintMembership(dAtA, i, uint64(m.MemberAttributes.Size()))
		n2, err := m.MemberAttributes.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	return i, nil
}

func (m *ClusterVersionSetRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterVersionSetRequest) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Ver) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintMembership(dAtA, i, uint64(len(m.Ver)))
		i += copy(dAtA[i:], m.Ver)
	}
	return i, nil
}

func (m *ClusterMemberAttrSetRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterMemberAttrSetRequest) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Member_ID != 0 {
		dAtA[i] = 0x8
		i++
		i = encodeVarintMembership(dAtA, i, uint64(m.Member_ID))
	}
	if m.MemberAttributes != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintMembership(dAtA, i, uint64(m.MemberAttributes.Size()))
		n3, err := m.MemberAttributes.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n3
	}
	return i, nil
}

func encodeVarintMembership(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *RaftAttributes) Size() (n int) {
	var l int
	_ = l
	if len(m.PeerUrls) > 0 {
		for _, s := range m.PeerUrls {
			l = len(s)
			n += 1 + l + sovMembership(uint64(l))
		}
	}
	if m.IsLearner {
		n += 2
	}
	return n
}

func (m *Attributes) Size() (n int) {
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovMembership(uint64(l))
	}
	if len(m.ClientUrls) > 0 {
		for _, s := range m.ClientUrls {
			l = len(s)
			n += 1 + l + sovMembership(uint64(l))
		}
	}
	return n
}

func (m *Member) Size() (n int) {
	var l int
	_ = l
	if m.ID != 0 {
		n += 1 + sovMembership(uint64(m.ID))
	}
	if m.RaftAttributes != nil {
		l = m.RaftAttributes.Size()
		n += 1 + l + sovMembership(uint64(l))
	}
	if m.MemberAttributes != nil {
		l = m.MemberAttributes.Size()
		n += 1 + l + sovMembership(uint64(l))
	}
	return n
}

func (m *ClusterVersionSetRequest) Size() (n int) {
	var l int
	_ = l
	l = len(m.Ver)
	if l > 0 {
		n += 1 + l + sovMembership(uint64(l))
	}
	return n
}

func (m *ClusterMemberAttrSetRequest) Size() (n int) {
	var l int
	_ = l
	if m.Member_ID != 0 {
		n += 1 + sovMembership(uint64(m.Member_ID))
	}
	if m.MemberAttributes != nil {
		l = m.MemberAttributes.Size()
		n += 1 + l + sovMembership(uint64(l))
	}
	return n
}

func sovMembership(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozMembership(x uint64) (n int) {
	return sovMembership(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *RaftAttributes) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMembership
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: RaftAttributes: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: RaftAttributes: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PeerUrls", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMembership
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PeerUrls = append(m.PeerUrls, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field IsLearner", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.IsLearner = bool(v != 0)
		default:
			iNdEx = preIndex
			skippy, err := skipMembership(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMembership
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Attributes) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMembership
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Attributes: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Attributes: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMembership
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ClientUrls", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMembership
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ClientUrls = append(m.ClientUrls, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMembership(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMembership
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Member) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMembership
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Member: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Member: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ID", wireType)
			}
			m.ID = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ID |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RaftAttributes", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMembership
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.RaftAttributes == nil {
				m.RaftAttributes = &RaftAttributes{}
			}
			if err := m.RaftAttributes.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MemberAttributes", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMembership
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.MemberAttributes == nil {
				m.MemberAttributes = &Attributes{}
			}
			if err := m.MemberAttributes.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMembership(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMembership
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ClusterVersionSetRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMembership
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterVersionSetRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterVersionSetRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Ver", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMembership
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Ver = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMembership(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMembership
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ClusterMemberAttrSetRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMembership
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterMemberAttrSetRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterMemberAttrSetRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Member_ID", wireType)
			}
			m.Member_ID = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Member_ID |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MemberAttributes", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMembership
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.MemberAttributes == nil {
				m.MemberAttributes = &Attributes{}
			}
			if err := m.MemberAttributes.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMembership(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMembership
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipMembership(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMembership
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
					return 0, ErrIntOverflowMembership
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMembership
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
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthMembership
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowMembership
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipMembership(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthMembership = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMembership   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("membership.proto", fileDescriptorMembership) }

var fileDescriptorMembership = []byte{
	// 333 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x92, 0x41, 0x4e, 0xc2, 0x40,
	0x14, 0x86, 0x99, 0x42, 0x08, 0x7d, 0x18, 0xc4, 0x09, 0x8b, 0x46, 0xb4, 0x92, 0xae, 0x58, 0x18,
	0x4c, 0xf4, 0x04, 0x28, 0x2c, 0x48, 0x60, 0x33, 0x46, 0xb7, 0xa4, 0x35, 0x0f, 0x6c, 0x52, 0xda,
	0xfa, 0x66, 0xea, 0xde, 0x5b, 0x78, 0x02, 0xcf, 0xc2, 0xd2, 0x23, 0x28, 0x5e, 0xc4, 0x74, 0xa6,
	0x81, 0x36, 0x71, 0xe3, 0xee, 0xe5, 0xef, 0xff, 0xbe, 0xf7, 0xff, 0xcd, 0x40, 0x77, 0x83, 0x9b,
	0x00, 0x49, 0x3e, 0x87, 0xe9, 0x28, 0xa5, 0x44, 0x25, 0xfc, 0xe8, 0xa0, 0xa4, 0xc1, 0x69, 0x6f,
	0x9d, 0xac, 0x13, 0xfd, 0xe1, 0x2a, 0x9f, 0x8c, 0xc7, 0x9b, 0x43, 0x47, 0xf8, 0x2b, 0x35, 0x56,
	0x8a, 0xc2, 0x20, 0x53, 0x28, 0x79, 0x1f, 0xec, 0x14, 0x91, 0x96, 0x19, 0x45, 0xd2, 0x61, 0x83,
	0xfa, 0xd0, 0x16, 0xad, 0x5c, 0x78, 0xa0, 0x48, 0xf2, 0x73, 0x80, 0x50, 0x2e, 0x23, 0xf4, 0x29,
	0x46, 0x72, 0xac, 0x01, 0x1b, 0xb6, 0x84, 0x1d, 0xca, 0xb9, 0x11, 0xbc, 0x31, 0x40, 0x89, 0xc4,
	0xa1, 0x11, 0xfb, 0x1b, 0x74, 0xd8, 0x80, 0x0d, 0x6d, 0xa1, 0x67, 0x7e, 0x01, 0xed, 0xa7, 0x28,
	0xc4, 0x58, 0x19, 0xbe, 0xa5, 0xf9, 0x60, 0xa4, 0xfc, 0x82, 0xf7, 0xc1, 0xa0, 0xb9, 0xd0, 0xb9,
	0x79, 0x07, 0xac, 0xd9, 0x44, 0x6f, 0x37, 0x84, 0x35, 0x9b, 0xf0, 0x29, 0x1c, 0x93, 0xbf, 0x52,
	0x4b, 0x7f, 0x7f, 0x42, 0x27, 0x68, 0x5f, 0x9f, 0x8d, 0xca, 0x4d, 0x47, 0xd5, 0x42, 0xa2, 0x43,
	0xd5, 0x82, 0x53, 0x38, 0x31, 0xf6, 0x32, 0xa8, 0xae, 0x41, 0x4e, 0x15, 0x54, 0x82, 0x14, 0x7f,
	0xf7, 0xa0, 0x78, 0x97, 0xe0, 0xdc, 0x45, 0x99, 0x54, 0x48, 0x8f, 0x48, 0x32, 0x4c, 0xe2, 0x7b,
	0x54, 0x02, 0x5f, 0x32, 0x94, 0x8a, 0x77, 0xa1, 0xfe, 0x8a, 0x54, 0x14, 0xcf, 0x47, 0xef, 0x8d,
	0x41, 0xbf, 0xb0, 0x2f, 0xf6, 0xa4, 0xd2, 0x46, 0x1f, 0xec, 0x22, 0xd4, 0xbe, 0x72, 0xcb, 0x08,
	0xba, 0xf8, 0x1f, 0x89, 0xad, 0xff, 0x26, 0xbe, 0xed, 0x6d, 0xbf, 0xdd, 0xda, 0x76, 0xe7, 0xb2,
	0xcf, 0x9d, 0xcb, 0xbe, 0x76, 0x2e, 0x7b, 0xff, 0x71, 0x6b, 0x41, 0x53, 0x3f, 0x84, 0x9b, 0xdf,
	0x00, 0x00, 0x00, 0xff, 0xff, 0x24, 0x78, 0x39, 0x52, 0x40, 0x02, 0x00, 0x00,
}
