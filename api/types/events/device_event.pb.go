// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: teleport/legacy/types/events/device_event.proto

package events

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

// DeviceEvent is a device-related event.
// The event type (Metadata.Type) for device events is always "device". See the
// event code (Metadata.Code) for its meaning.
type DeviceEvent struct {
	// Metadata holds common event metadata.
	Metadata `protobuf:"bytes,1,opt,name=metadata,proto3,embedded=metadata" json:""`
	// Status indicates the outcome of the event.
	Status *Status `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
	// DeviceMetadata holds metadata about the user device.
	Device *DeviceMetadata `protobuf:"bytes,3,opt,name=device,proto3" json:"device,omitempty"`
	// UserMetadata holds metadata about the user behind the event.
	User                 *UserMetadata `protobuf:"bytes,4,opt,name=user,proto3" json:"user,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *DeviceEvent) Reset()         { *m = DeviceEvent{} }
func (m *DeviceEvent) String() string { return proto.CompactTextString(m) }
func (*DeviceEvent) ProtoMessage()    {}
func (*DeviceEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_0ba5289cd1134e03, []int{0}
}
func (m *DeviceEvent) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *DeviceEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_DeviceEvent.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *DeviceEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DeviceEvent.Merge(m, src)
}
func (m *DeviceEvent) XXX_Size() int {
	return m.Size()
}
func (m *DeviceEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_DeviceEvent.DiscardUnknown(m)
}

var xxx_messageInfo_DeviceEvent proto.InternalMessageInfo

func init() {
	proto.RegisterType((*DeviceEvent)(nil), "events.DeviceEvent")
}

func init() {
	proto.RegisterFile("teleport/legacy/types/events/device_event.proto", fileDescriptor_0ba5289cd1134e03)
}

var fileDescriptor_0ba5289cd1134e03 = []byte{
	// 281 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x91, 0x3f, 0x4b, 0xc3, 0x40,
	0x18, 0xc6, 0x73, 0x5a, 0x82, 0x5c, 0x45, 0x24, 0x14, 0x09, 0x1d, 0x12, 0x71, 0x90, 0xba, 0xe4,
	0x20, 0x6e, 0x8e, 0xa5, 0x8e, 0x2e, 0x11, 0x17, 0x17, 0xb9, 0xa6, 0x2f, 0x31, 0x90, 0xf6, 0xc2,
	0xdd, 0x9b, 0x40, 0xbf, 0x61, 0xc0, 0xa5, 0x9f, 0x20, 0x68, 0x46, 0x3f, 0x85, 0xf4, 0xfe, 0x54,
	0x5c, 0xa4, 0x53, 0x72, 0xcf, 0xf3, 0x7b, 0x9e, 0x7b, 0x79, 0x8f, 0x32, 0x84, 0x0a, 0x6a, 0x21,
	0x91, 0x55, 0x50, 0xf0, 0x7c, 0xcb, 0x70, 0x5b, 0x83, 0x62, 0xd0, 0xc2, 0x06, 0x15, 0x5b, 0x41,
	0x5b, 0xe6, 0xf0, 0xa6, 0x4f, 0x49, 0x2d, 0x05, 0x8a, 0xc0, 0x37, 0xd6, 0x74, 0x52, 0x88, 0x42,
	0x68, 0x89, 0xed, 0xff, 0x8c, 0x3b, 0x4d, 0x8f, 0xa9, 0x5b, 0x03, 0xf2, 0x15, 0x47, 0x6e, 0x33,
	0x77, 0xff, 0x66, 0xcc, 0xc7, 0xa0, 0x37, 0x1f, 0x84, 0x8e, 0x17, 0xba, 0xe4, 0x71, 0x2f, 0x07,
	0x0f, 0xf4, 0xcc, 0x95, 0x85, 0xe4, 0x9a, 0xcc, 0xc6, 0xe9, 0x65, 0x62, 0x03, 0x4f, 0x56, 0x9f,
	0x9f, 0x77, 0x7d, 0xec, 0xed, 0xfa, 0x98, 0x7c, 0xf7, 0xb1, 0x97, 0x1d, 0xf8, 0xe0, 0x96, 0xfa,
	0x0a, 0x39, 0x36, 0x2a, 0x3c, 0xd1, 0xc9, 0x0b, 0x97, 0x7c, 0xd6, 0x6a, 0x66, 0xdd, 0x20, 0xa1,
	0xbe, 0x99, 0x3b, 0x3c, 0xd5, 0xdc, 0x95, 0xe3, 0xcc, 0x20, 0xee, 0x9e, 0xcc, 0x52, 0xc1, 0x8c,
	0x8e, 0x1a, 0x05, 0x32, 0x1c, 0x69, 0x7a, 0xe2, 0xe8, 0x17, 0x05, 0xf2, 0xc0, 0x6a, 0x62, 0xbe,
	0xe8, 0xbe, 0x22, 0xaf, 0x1b, 0x22, 0xb2, 0x1b, 0x22, 0xf2, 0x39, 0x44, 0xe4, 0x35, 0x2d, 0x4a,
	0x7c, 0x6f, 0x96, 0x49, 0x2e, 0xd6, 0xac, 0x90, 0xbc, 0x2d, 0x91, 0x63, 0x29, 0x36, 0xbc, 0xfa,
	0x7d, 0x26, 0x5e, 0x97, 0x7f, 0x16, 0xb4, 0xf4, 0xf5, 0x6a, 0xee, 0x7f, 0x02, 0x00, 0x00, 0xff,
	0xff, 0x5a, 0x47, 0xae, 0xe1, 0xca, 0x01, 0x00, 0x00,
}

func (m *DeviceEvent) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DeviceEvent) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *DeviceEvent) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.User != nil {
		{
			size, err := m.User.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintDeviceEvent(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x22
	}
	if m.Device != nil {
		{
			size, err := m.Device.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintDeviceEvent(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.Status != nil {
		{
			size, err := m.Status.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintDeviceEvent(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	{
		size, err := m.Metadata.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintDeviceEvent(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func encodeVarintDeviceEvent(dAtA []byte, offset int, v uint64) int {
	offset -= sovDeviceEvent(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *DeviceEvent) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.Metadata.Size()
	n += 1 + l + sovDeviceEvent(uint64(l))
	if m.Status != nil {
		l = m.Status.Size()
		n += 1 + l + sovDeviceEvent(uint64(l))
	}
	if m.Device != nil {
		l = m.Device.Size()
		n += 1 + l + sovDeviceEvent(uint64(l))
	}
	if m.User != nil {
		l = m.User.Size()
		n += 1 + l + sovDeviceEvent(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovDeviceEvent(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozDeviceEvent(x uint64) (n int) {
	return sovDeviceEvent(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *DeviceEvent) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDeviceEvent
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
			return fmt.Errorf("proto: DeviceEvent: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DeviceEvent: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Metadata", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeviceEvent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDeviceEvent
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDeviceEvent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Metadata.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeviceEvent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDeviceEvent
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDeviceEvent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Status == nil {
				m.Status = &Status{}
			}
			if err := m.Status.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Device", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeviceEvent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDeviceEvent
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDeviceEvent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Device == nil {
				m.Device = &DeviceMetadata{}
			}
			if err := m.Device.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field User", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeviceEvent
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDeviceEvent
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDeviceEvent
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.User == nil {
				m.User = &UserMetadata{}
			}
			if err := m.User.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipDeviceEvent(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthDeviceEvent
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
func skipDeviceEvent(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowDeviceEvent
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
					return 0, ErrIntOverflowDeviceEvent
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
					return 0, ErrIntOverflowDeviceEvent
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
				return 0, ErrInvalidLengthDeviceEvent
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupDeviceEvent
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthDeviceEvent
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthDeviceEvent        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowDeviceEvent          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupDeviceEvent = fmt.Errorf("proto: unexpected end of group")
)
