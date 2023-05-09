// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        (unknown)
// source: teleport/assist/v1/assist.proto

package assist

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// GetAssistantMessagesRequest is a request to the assistant service.
type GetAssistantMessagesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ConversationId identifies a conversation.
	// It's used to tie all messages in a one conversation.
	ConversationId string `protobuf:"bytes,1,opt,name=conversation_id,json=conversationId,proto3" json:"conversation_id,omitempty"`
	// username is a username of the user who sent the message.
	Username string `protobuf:"bytes,2,opt,name=username,proto3" json:"username,omitempty"`
}

func (x *GetAssistantMessagesRequest) Reset() {
	*x = GetAssistantMessagesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assist_v1_assist_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAssistantMessagesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAssistantMessagesRequest) ProtoMessage() {}

func (x *GetAssistantMessagesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assist_v1_assist_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAssistantMessagesRequest.ProtoReflect.Descriptor instead.
func (*GetAssistantMessagesRequest) Descriptor() ([]byte, []int) {
	return file_teleport_assist_v1_assist_proto_rawDescGZIP(), []int{0}
}

func (x *GetAssistantMessagesRequest) GetConversationId() string {
	if x != nil {
		return x.ConversationId
	}
	return ""
}

func (x *GetAssistantMessagesRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

// AssistantMessage is a message sent to the assistant service. The conversation
// must be created first.
type AssistantMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ConversationId is used to tie all messages into a conversation.
	ConversationId string `protobuf:"bytes,1,opt,name=conversation_id,json=conversationId,proto3" json:"conversation_id,omitempty"`
	// username is a username of the user who sent the message.
	Username string `protobuf:"bytes,2,opt,name=username,proto3" json:"username,omitempty"`
	// type is a type of message. It can be Chat response/query or a command to run.
	Type string `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty"`
	// CreatedTime is the time when the event occurred.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=created_time,json=createdTime,proto3" json:"created_time,omitempty"`
	// payload is a JSON message
	Payload string `protobuf:"bytes,5,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (x *AssistantMessage) Reset() {
	*x = AssistantMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assist_v1_assist_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AssistantMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AssistantMessage) ProtoMessage() {}

func (x *AssistantMessage) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assist_v1_assist_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AssistantMessage.ProtoReflect.Descriptor instead.
func (*AssistantMessage) Descriptor() ([]byte, []int) {
	return file_teleport_assist_v1_assist_proto_rawDescGZIP(), []int{1}
}

func (x *AssistantMessage) GetConversationId() string {
	if x != nil {
		return x.ConversationId
	}
	return ""
}

func (x *AssistantMessage) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *AssistantMessage) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *AssistantMessage) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *AssistantMessage) GetPayload() string {
	if x != nil {
		return x.Payload
	}
	return ""
}

// CreateAssistantMessageRequest is a request to the assistant service.
type CreateAssistantMessageRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// message is a message sent to the assistant service.
	Message *AssistantMessage `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *CreateAssistantMessageRequest) Reset() {
	*x = CreateAssistantMessageRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assist_v1_assist_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateAssistantMessageRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateAssistantMessageRequest) ProtoMessage() {}

func (x *CreateAssistantMessageRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assist_v1_assist_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateAssistantMessageRequest.ProtoReflect.Descriptor instead.
func (*CreateAssistantMessageRequest) Descriptor() ([]byte, []int) {
	return file_teleport_assist_v1_assist_proto_rawDescGZIP(), []int{2}
}

func (x *CreateAssistantMessageRequest) GetMessage() *AssistantMessage {
	if x != nil {
		return x.Message
	}
	return nil
}

// GetAssistantMessagesResponse is a response from the assistant service.
type GetAssistantMessagesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// messages is a list of messages.
	Messages []*AssistantMessage `protobuf:"bytes,1,rep,name=messages,proto3" json:"messages,omitempty"`
}

func (x *GetAssistantMessagesResponse) Reset() {
	*x = GetAssistantMessagesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assist_v1_assist_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAssistantMessagesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAssistantMessagesResponse) ProtoMessage() {}

func (x *GetAssistantMessagesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assist_v1_assist_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAssistantMessagesResponse.ProtoReflect.Descriptor instead.
func (*GetAssistantMessagesResponse) Descriptor() ([]byte, []int) {
	return file_teleport_assist_v1_assist_proto_rawDescGZIP(), []int{3}
}

func (x *GetAssistantMessagesResponse) GetMessages() []*AssistantMessage {
	if x != nil {
		return x.Messages
	}
	return nil
}

// GetAssistantConversationsRequest is a request to get a list of conversations.
type GetAssistantConversationsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// username is a username of the user who created the conversation.
	Username string `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
}

func (x *GetAssistantConversationsRequest) Reset() {
	*x = GetAssistantConversationsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assist_v1_assist_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAssistantConversationsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAssistantConversationsRequest) ProtoMessage() {}

func (x *GetAssistantConversationsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assist_v1_assist_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAssistantConversationsRequest.ProtoReflect.Descriptor instead.
func (*GetAssistantConversationsRequest) Descriptor() ([]byte, []int) {
	return file_teleport_assist_v1_assist_proto_rawDescGZIP(), []int{4}
}

func (x *GetAssistantConversationsRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

// ConversationInfo is a conversation info. It contains a conversation
// information like ID, title, created time.
type ConversationInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// id is a unique conversation ID.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// title is a title of the conversation.
	Title string `protobuf:"bytes,2,opt,name=title,proto3" json:"title,omitempty"`
	// createdTime is the time when the conversation was created.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=created_time,json=createdTime,proto3" json:"created_time,omitempty"`
}

func (x *ConversationInfo) Reset() {
	*x = ConversationInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assist_v1_assist_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConversationInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConversationInfo) ProtoMessage() {}

func (x *ConversationInfo) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assist_v1_assist_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConversationInfo.ProtoReflect.Descriptor instead.
func (*ConversationInfo) Descriptor() ([]byte, []int) {
	return file_teleport_assist_v1_assist_proto_rawDescGZIP(), []int{5}
}

func (x *ConversationInfo) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ConversationInfo) GetTitle() string {
	if x != nil {
		return x.Title
	}
	return ""
}

func (x *ConversationInfo) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

// GetAssistantConversationsResponse is a response from the assistant service.
type GetAssistantConversationsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// conversations is a list of conversations.
	Conversations []*ConversationInfo `protobuf:"bytes,1,rep,name=conversations,proto3" json:"conversations,omitempty"`
}

func (x *GetAssistantConversationsResponse) Reset() {
	*x = GetAssistantConversationsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assist_v1_assist_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAssistantConversationsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAssistantConversationsResponse) ProtoMessage() {}

func (x *GetAssistantConversationsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assist_v1_assist_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAssistantConversationsResponse.ProtoReflect.Descriptor instead.
func (*GetAssistantConversationsResponse) Descriptor() ([]byte, []int) {
	return file_teleport_assist_v1_assist_proto_rawDescGZIP(), []int{6}
}

func (x *GetAssistantConversationsResponse) GetConversations() []*ConversationInfo {
	if x != nil {
		return x.Conversations
	}
	return nil
}

// CreateAssistantConversationRequest is a request to create a new conversation.
type CreateAssistantConversationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// username is a username of the user who created the conversation.
	Username string `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	// createdTime is the time when the conversation was created.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=created_time,json=createdTime,proto3" json:"created_time,omitempty"`
}

func (x *CreateAssistantConversationRequest) Reset() {
	*x = CreateAssistantConversationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assist_v1_assist_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateAssistantConversationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateAssistantConversationRequest) ProtoMessage() {}

func (x *CreateAssistantConversationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assist_v1_assist_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateAssistantConversationRequest.ProtoReflect.Descriptor instead.
func (*CreateAssistantConversationRequest) Descriptor() ([]byte, []int) {
	return file_teleport_assist_v1_assist_proto_rawDescGZIP(), []int{7}
}

func (x *CreateAssistantConversationRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *CreateAssistantConversationRequest) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

// CreateAssistantConversationResponse is a response from the assistant service.
type CreateAssistantConversationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// id is a unique conversation ID.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *CreateAssistantConversationResponse) Reset() {
	*x = CreateAssistantConversationResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assist_v1_assist_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateAssistantConversationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateAssistantConversationResponse) ProtoMessage() {}

func (x *CreateAssistantConversationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assist_v1_assist_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateAssistantConversationResponse.ProtoReflect.Descriptor instead.
func (*CreateAssistantConversationResponse) Descriptor() ([]byte, []int) {
	return file_teleport_assist_v1_assist_proto_rawDescGZIP(), []int{8}
}

func (x *CreateAssistantConversationResponse) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

// UpdateAssistantConversationInfoRequest is a request to update the conversation info.
type UpdateAssistantConversationInfoRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// conversationId is a unique conversation ID.
	ConversationId string `protobuf:"bytes,1,opt,name=conversation_id,json=conversationId,proto3" json:"conversation_id,omitempty"`
	// username is a username of the user who created the conversation.
	Username string `protobuf:"bytes,2,opt,name=username,proto3" json:"username,omitempty"`
	// title is a title of the conversation.
	Title string `protobuf:"bytes,3,opt,name=title,proto3" json:"title,omitempty"`
}

func (x *UpdateAssistantConversationInfoRequest) Reset() {
	*x = UpdateAssistantConversationInfoRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_assist_v1_assist_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateAssistantConversationInfoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateAssistantConversationInfoRequest) ProtoMessage() {}

func (x *UpdateAssistantConversationInfoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_assist_v1_assist_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateAssistantConversationInfoRequest.ProtoReflect.Descriptor instead.
func (*UpdateAssistantConversationInfoRequest) Descriptor() ([]byte, []int) {
	return file_teleport_assist_v1_assist_proto_rawDescGZIP(), []int{9}
}

func (x *UpdateAssistantConversationInfoRequest) GetConversationId() string {
	if x != nil {
		return x.ConversationId
	}
	return ""
}

func (x *UpdateAssistantConversationInfoRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *UpdateAssistantConversationInfoRequest) GetTitle() string {
	if x != nil {
		return x.Title
	}
	return ""
}

var File_teleport_assist_v1_assist_proto protoreflect.FileDescriptor

var file_teleport_assist_v1_assist_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x73, 0x73, 0x69, 0x73,
	0x74, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x12, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69,
	0x73, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x62, 0x0a, 0x1b, 0x47, 0x65, 0x74, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74,
	0x61, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x27, 0x0a, 0x0f, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x63, 0x6f, 0x6e,
	0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x75,
	0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75,
	0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0xc4, 0x01, 0x0a, 0x10, 0x41, 0x73, 0x73, 0x69,
	0x73, 0x74, 0x61, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x27, 0x0a, 0x0f,
	0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x3d, 0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x54, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0x5f,
	0x0a, 0x1d, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e,
	0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x3e, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x24, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69,
	0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22,
	0x60, 0x0a, 0x1c, 0x47, 0x65, 0x74, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x40, 0x0a, 0x08, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x24, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73,
	0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x08, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x73, 0x22, 0x3e, 0x0a, 0x20, 0x47, 0x65, 0x74, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e,
	0x74, 0x43, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x22, 0x77, 0x0a, 0x10, 0x43, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x12, 0x3d, 0x0a, 0x0c, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0b, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x22, 0x6f, 0x0a, 0x21, 0x47, 0x65,
	0x74, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x76, 0x65, 0x72,
	0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x4a, 0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6f, 0x6e, 0x76,
	0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0d, 0x63, 0x6f,
	0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x7f, 0x0a, 0x22, 0x43,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x43, 0x6f,
	0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x3d, 0x0a,
	0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x22, 0x35, 0x0a, 0x23,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x43,
	0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x02, 0x69, 0x64, 0x22, 0x83, 0x01, 0x0a, 0x26, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x41, 0x73,
	0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x27,
	0x0a, 0x0f, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x32, 0x82, 0x05, 0x0a, 0x0d, 0x41, 0x73,
	0x73, 0x69, 0x73, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x8e, 0x01, 0x0a, 0x1b,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x43,
	0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x36, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31,
	0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74,
	0x43, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x37, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61,
	0x73, 0x73, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41,
	0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x88, 0x01, 0x0a,
	0x19, 0x47, 0x65, 0x74, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e,
	0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x34, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e,
	0x47, 0x65, 0x74, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x76,
	0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x35, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69,
	0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61,
	0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x79, 0x0a, 0x14, 0x47, 0x65, 0x74, 0x41, 0x73,
	0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x12,
	0x2f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73,
	0x74, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e,
	0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x30, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69,
	0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61,
	0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x63, 0x0a, 0x16, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x73, 0x73, 0x69,
	0x73, 0x74, 0x61, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x31, 0x2e, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x2e, 0x76,
	0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e,
	0x74, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x75, 0x0a, 0x1f, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x76, 0x65, 0x72,
	0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x3a, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x41, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x43,
	0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x42, 0x45,
	0x5a, 0x43, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61,
	0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x2f, 0x76, 0x31, 0x3b, 0x61,
	0x73, 0x73, 0x69, 0x73, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_assist_v1_assist_proto_rawDescOnce sync.Once
	file_teleport_assist_v1_assist_proto_rawDescData = file_teleport_assist_v1_assist_proto_rawDesc
)

func file_teleport_assist_v1_assist_proto_rawDescGZIP() []byte {
	file_teleport_assist_v1_assist_proto_rawDescOnce.Do(func() {
		file_teleport_assist_v1_assist_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_assist_v1_assist_proto_rawDescData)
	})
	return file_teleport_assist_v1_assist_proto_rawDescData
}

var file_teleport_assist_v1_assist_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_teleport_assist_v1_assist_proto_goTypes = []interface{}{
	(*GetAssistantMessagesRequest)(nil),            // 0: teleport.assist.v1.GetAssistantMessagesRequest
	(*AssistantMessage)(nil),                       // 1: teleport.assist.v1.AssistantMessage
	(*CreateAssistantMessageRequest)(nil),          // 2: teleport.assist.v1.CreateAssistantMessageRequest
	(*GetAssistantMessagesResponse)(nil),           // 3: teleport.assist.v1.GetAssistantMessagesResponse
	(*GetAssistantConversationsRequest)(nil),       // 4: teleport.assist.v1.GetAssistantConversationsRequest
	(*ConversationInfo)(nil),                       // 5: teleport.assist.v1.ConversationInfo
	(*GetAssistantConversationsResponse)(nil),      // 6: teleport.assist.v1.GetAssistantConversationsResponse
	(*CreateAssistantConversationRequest)(nil),     // 7: teleport.assist.v1.CreateAssistantConversationRequest
	(*CreateAssistantConversationResponse)(nil),    // 8: teleport.assist.v1.CreateAssistantConversationResponse
	(*UpdateAssistantConversationInfoRequest)(nil), // 9: teleport.assist.v1.UpdateAssistantConversationInfoRequest
	(*timestamppb.Timestamp)(nil),                  // 10: google.protobuf.Timestamp
	(*emptypb.Empty)(nil),                          // 11: google.protobuf.Empty
}
var file_teleport_assist_v1_assist_proto_depIdxs = []int32{
	10, // 0: teleport.assist.v1.AssistantMessage.created_time:type_name -> google.protobuf.Timestamp
	1,  // 1: teleport.assist.v1.CreateAssistantMessageRequest.message:type_name -> teleport.assist.v1.AssistantMessage
	1,  // 2: teleport.assist.v1.GetAssistantMessagesResponse.messages:type_name -> teleport.assist.v1.AssistantMessage
	10, // 3: teleport.assist.v1.ConversationInfo.created_time:type_name -> google.protobuf.Timestamp
	5,  // 4: teleport.assist.v1.GetAssistantConversationsResponse.conversations:type_name -> teleport.assist.v1.ConversationInfo
	10, // 5: teleport.assist.v1.CreateAssistantConversationRequest.created_time:type_name -> google.protobuf.Timestamp
	7,  // 6: teleport.assist.v1.AssistService.CreateAssistantConversation:input_type -> teleport.assist.v1.CreateAssistantConversationRequest
	4,  // 7: teleport.assist.v1.AssistService.GetAssistantConversations:input_type -> teleport.assist.v1.GetAssistantConversationsRequest
	0,  // 8: teleport.assist.v1.AssistService.GetAssistantMessages:input_type -> teleport.assist.v1.GetAssistantMessagesRequest
	2,  // 9: teleport.assist.v1.AssistService.CreateAssistantMessage:input_type -> teleport.assist.v1.CreateAssistantMessageRequest
	9,  // 10: teleport.assist.v1.AssistService.UpdateAssistantConversationInfo:input_type -> teleport.assist.v1.UpdateAssistantConversationInfoRequest
	8,  // 11: teleport.assist.v1.AssistService.CreateAssistantConversation:output_type -> teleport.assist.v1.CreateAssistantConversationResponse
	6,  // 12: teleport.assist.v1.AssistService.GetAssistantConversations:output_type -> teleport.assist.v1.GetAssistantConversationsResponse
	3,  // 13: teleport.assist.v1.AssistService.GetAssistantMessages:output_type -> teleport.assist.v1.GetAssistantMessagesResponse
	11, // 14: teleport.assist.v1.AssistService.CreateAssistantMessage:output_type -> google.protobuf.Empty
	11, // 15: teleport.assist.v1.AssistService.UpdateAssistantConversationInfo:output_type -> google.protobuf.Empty
	11, // [11:16] is the sub-list for method output_type
	6,  // [6:11] is the sub-list for method input_type
	6,  // [6:6] is the sub-list for extension type_name
	6,  // [6:6] is the sub-list for extension extendee
	0,  // [0:6] is the sub-list for field type_name
}

func init() { file_teleport_assist_v1_assist_proto_init() }
func file_teleport_assist_v1_assist_proto_init() {
	if File_teleport_assist_v1_assist_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_assist_v1_assist_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAssistantMessagesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assist_v1_assist_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AssistantMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assist_v1_assist_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateAssistantMessageRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assist_v1_assist_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAssistantMessagesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assist_v1_assist_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAssistantConversationsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assist_v1_assist_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConversationInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assist_v1_assist_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAssistantConversationsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assist_v1_assist_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateAssistantConversationRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assist_v1_assist_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateAssistantConversationResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_assist_v1_assist_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateAssistantConversationInfoRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_assist_v1_assist_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_assist_v1_assist_proto_goTypes,
		DependencyIndexes: file_teleport_assist_v1_assist_proto_depIdxs,
		MessageInfos:      file_teleport_assist_v1_assist_proto_msgTypes,
	}.Build()
	File_teleport_assist_v1_assist_proto = out.File
	file_teleport_assist_v1_assist_proto_rawDesc = nil
	file_teleport_assist_v1_assist_proto_goTypes = nil
	file_teleport_assist_v1_assist_proto_depIdxs = nil
}
