// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/firestore/admin/v1/operation.proto

package admin

import (
	fmt "fmt"
	math "math"

	proto "github.com/golang/protobuf/proto"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	_ "google.golang.org/genproto/googleapis/api/annotations"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Describes the state of the operation.
type OperationState int32

const (
	// Unspecified.
	OperationState_OPERATION_STATE_UNSPECIFIED OperationState = 0
	// Request is being prepared for processing.
	OperationState_INITIALIZING OperationState = 1
	// Request is actively being processed.
	OperationState_PROCESSING OperationState = 2
	// Request is in the process of being cancelled after user called
	// google.longrunning.Operations.CancelOperation on the operation.
	OperationState_CANCELLING OperationState = 3
	// Request has been processed and is in its finalization stage.
	OperationState_FINALIZING OperationState = 4
	// Request has completed successfully.
	OperationState_SUCCESSFUL OperationState = 5
	// Request has finished being processed, but encountered an error.
	OperationState_FAILED OperationState = 6
	// Request has finished being cancelled after user called
	// google.longrunning.Operations.CancelOperation.
	OperationState_CANCELLED OperationState = 7
)

var OperationState_name = map[int32]string{
	0: "OPERATION_STATE_UNSPECIFIED",
	1: "INITIALIZING",
	2: "PROCESSING",
	3: "CANCELLING",
	4: "FINALIZING",
	5: "SUCCESSFUL",
	6: "FAILED",
	7: "CANCELLED",
}

var OperationState_value = map[string]int32{
	"OPERATION_STATE_UNSPECIFIED": 0,
	"INITIALIZING":                1,
	"PROCESSING":                  2,
	"CANCELLING":                  3,
	"FINALIZING":                  4,
	"SUCCESSFUL":                  5,
	"FAILED":                      6,
	"CANCELLED":                   7,
}

func (x OperationState) String() string {
	return proto.EnumName(OperationState_name, int32(x))
}

func (OperationState) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_f3b79aaf4866e7e0, []int{0}
}

// Specifies how the index is changing.
type FieldOperationMetadata_IndexConfigDelta_ChangeType int32

const (
	// The type of change is not specified or known.
	FieldOperationMetadata_IndexConfigDelta_CHANGE_TYPE_UNSPECIFIED FieldOperationMetadata_IndexConfigDelta_ChangeType = 0
	// The single field index is being added.
	FieldOperationMetadata_IndexConfigDelta_ADD FieldOperationMetadata_IndexConfigDelta_ChangeType = 1
	// The single field index is being removed.
	FieldOperationMetadata_IndexConfigDelta_REMOVE FieldOperationMetadata_IndexConfigDelta_ChangeType = 2
)

var FieldOperationMetadata_IndexConfigDelta_ChangeType_name = map[int32]string{
	0: "CHANGE_TYPE_UNSPECIFIED",
	1: "ADD",
	2: "REMOVE",
}

var FieldOperationMetadata_IndexConfigDelta_ChangeType_value = map[string]int32{
	"CHANGE_TYPE_UNSPECIFIED": 0,
	"ADD":                     1,
	"REMOVE":                  2,
}

func (x FieldOperationMetadata_IndexConfigDelta_ChangeType) String() string {
	return proto.EnumName(FieldOperationMetadata_IndexConfigDelta_ChangeType_name, int32(x))
}

func (FieldOperationMetadata_IndexConfigDelta_ChangeType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_f3b79aaf4866e7e0, []int{1, 0, 0}
}

// Metadata for [google.longrunning.Operation][google.longrunning.Operation] results from
// [FirestoreAdmin.CreateIndex][google.firestore.admin.v1.FirestoreAdmin.CreateIndex].
type IndexOperationMetadata struct {
	// The time this operation started.
	StartTime *timestamp.Timestamp `protobuf:"bytes,1,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty"`
	// The time this operation completed. Will be unset if operation still in
	// progress.
	EndTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=end_time,json=endTime,proto3" json:"end_time,omitempty"`
	// The index resource that this operation is acting on. For example:
	// `projects/{project_id}/databases/{database_id}/collectionGroups/{collection_id}/indexes/{index_id}`
	Index string `protobuf:"bytes,3,opt,name=index,proto3" json:"index,omitempty"`
	// The state of the operation.
	State OperationState `protobuf:"varint,4,opt,name=state,proto3,enum=google.firestore.admin.v1.OperationState" json:"state,omitempty"`
	// The progress, in documents, of this operation.
	ProgressDocuments *Progress `protobuf:"bytes,5,opt,name=progress_documents,json=progressDocuments,proto3" json:"progress_documents,omitempty"`
	// The progress, in bytes, of this operation.
	ProgressBytes        *Progress `protobuf:"bytes,6,opt,name=progress_bytes,json=progressBytes,proto3" json:"progress_bytes,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *IndexOperationMetadata) Reset()         { *m = IndexOperationMetadata{} }
func (m *IndexOperationMetadata) String() string { return proto.CompactTextString(m) }
func (*IndexOperationMetadata) ProtoMessage()    {}
func (*IndexOperationMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_f3b79aaf4866e7e0, []int{0}
}

func (m *IndexOperationMetadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IndexOperationMetadata.Unmarshal(m, b)
}
func (m *IndexOperationMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IndexOperationMetadata.Marshal(b, m, deterministic)
}
func (m *IndexOperationMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IndexOperationMetadata.Merge(m, src)
}
func (m *IndexOperationMetadata) XXX_Size() int {
	return xxx_messageInfo_IndexOperationMetadata.Size(m)
}
func (m *IndexOperationMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_IndexOperationMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_IndexOperationMetadata proto.InternalMessageInfo

func (m *IndexOperationMetadata) GetStartTime() *timestamp.Timestamp {
	if m != nil {
		return m.StartTime
	}
	return nil
}

func (m *IndexOperationMetadata) GetEndTime() *timestamp.Timestamp {
	if m != nil {
		return m.EndTime
	}
	return nil
}

func (m *IndexOperationMetadata) GetIndex() string {
	if m != nil {
		return m.Index
	}
	return ""
}

func (m *IndexOperationMetadata) GetState() OperationState {
	if m != nil {
		return m.State
	}
	return OperationState_OPERATION_STATE_UNSPECIFIED
}

func (m *IndexOperationMetadata) GetProgressDocuments() *Progress {
	if m != nil {
		return m.ProgressDocuments
	}
	return nil
}

func (m *IndexOperationMetadata) GetProgressBytes() *Progress {
	if m != nil {
		return m.ProgressBytes
	}
	return nil
}

// Metadata for [google.longrunning.Operation][google.longrunning.Operation] results from
// [FirestoreAdmin.UpdateField][google.firestore.admin.v1.FirestoreAdmin.UpdateField].
type FieldOperationMetadata struct {
	// The time this operation started.
	StartTime *timestamp.Timestamp `protobuf:"bytes,1,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty"`
	// The time this operation completed. Will be unset if operation still in
	// progress.
	EndTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=end_time,json=endTime,proto3" json:"end_time,omitempty"`
	// The field resource that this operation is acting on. For example:
	// `projects/{project_id}/databases/{database_id}/collectionGroups/{collection_id}/fields/{field_path}`
	Field string `protobuf:"bytes,3,opt,name=field,proto3" json:"field,omitempty"`
	// A list of [IndexConfigDelta][google.firestore.admin.v1.FieldOperationMetadata.IndexConfigDelta], which describe the intent of this
	// operation.
	IndexConfigDeltas []*FieldOperationMetadata_IndexConfigDelta `protobuf:"bytes,4,rep,name=index_config_deltas,json=indexConfigDeltas,proto3" json:"index_config_deltas,omitempty"`
	// The state of the operation.
	State OperationState `protobuf:"varint,5,opt,name=state,proto3,enum=google.firestore.admin.v1.OperationState" json:"state,omitempty"`
	// The progress, in documents, of this operation.
	ProgressDocuments *Progress `protobuf:"bytes,6,opt,name=progress_documents,json=progressDocuments,proto3" json:"progress_documents,omitempty"`
	// The progress, in bytes, of this operation.
	ProgressBytes        *Progress `protobuf:"bytes,7,opt,name=progress_bytes,json=progressBytes,proto3" json:"progress_bytes,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *FieldOperationMetadata) Reset()         { *m = FieldOperationMetadata{} }
func (m *FieldOperationMetadata) String() string { return proto.CompactTextString(m) }
func (*FieldOperationMetadata) ProtoMessage()    {}
func (*FieldOperationMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_f3b79aaf4866e7e0, []int{1}
}

func (m *FieldOperationMetadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FieldOperationMetadata.Unmarshal(m, b)
}
func (m *FieldOperationMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FieldOperationMetadata.Marshal(b, m, deterministic)
}
func (m *FieldOperationMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FieldOperationMetadata.Merge(m, src)
}
func (m *FieldOperationMetadata) XXX_Size() int {
	return xxx_messageInfo_FieldOperationMetadata.Size(m)
}
func (m *FieldOperationMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_FieldOperationMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_FieldOperationMetadata proto.InternalMessageInfo

func (m *FieldOperationMetadata) GetStartTime() *timestamp.Timestamp {
	if m != nil {
		return m.StartTime
	}
	return nil
}

func (m *FieldOperationMetadata) GetEndTime() *timestamp.Timestamp {
	if m != nil {
		return m.EndTime
	}
	return nil
}

func (m *FieldOperationMetadata) GetField() string {
	if m != nil {
		return m.Field
	}
	return ""
}

func (m *FieldOperationMetadata) GetIndexConfigDeltas() []*FieldOperationMetadata_IndexConfigDelta {
	if m != nil {
		return m.IndexConfigDeltas
	}
	return nil
}

func (m *FieldOperationMetadata) GetState() OperationState {
	if m != nil {
		return m.State
	}
	return OperationState_OPERATION_STATE_UNSPECIFIED
}

func (m *FieldOperationMetadata) GetProgressDocuments() *Progress {
	if m != nil {
		return m.ProgressDocuments
	}
	return nil
}

func (m *FieldOperationMetadata) GetProgressBytes() *Progress {
	if m != nil {
		return m.ProgressBytes
	}
	return nil
}

// Information about an index configuration change.
type FieldOperationMetadata_IndexConfigDelta struct {
	// Specifies how the index is changing.
	ChangeType FieldOperationMetadata_IndexConfigDelta_ChangeType `protobuf:"varint,1,opt,name=change_type,json=changeType,proto3,enum=google.firestore.admin.v1.FieldOperationMetadata_IndexConfigDelta_ChangeType" json:"change_type,omitempty"`
	// The index being changed.
	Index                *Index   `protobuf:"bytes,2,opt,name=index,proto3" json:"index,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FieldOperationMetadata_IndexConfigDelta) Reset() {
	*m = FieldOperationMetadata_IndexConfigDelta{}
}
func (m *FieldOperationMetadata_IndexConfigDelta) String() string { return proto.CompactTextString(m) }
func (*FieldOperationMetadata_IndexConfigDelta) ProtoMessage()    {}
func (*FieldOperationMetadata_IndexConfigDelta) Descriptor() ([]byte, []int) {
	return fileDescriptor_f3b79aaf4866e7e0, []int{1, 0}
}

func (m *FieldOperationMetadata_IndexConfigDelta) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FieldOperationMetadata_IndexConfigDelta.Unmarshal(m, b)
}
func (m *FieldOperationMetadata_IndexConfigDelta) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FieldOperationMetadata_IndexConfigDelta.Marshal(b, m, deterministic)
}
func (m *FieldOperationMetadata_IndexConfigDelta) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FieldOperationMetadata_IndexConfigDelta.Merge(m, src)
}
func (m *FieldOperationMetadata_IndexConfigDelta) XXX_Size() int {
	return xxx_messageInfo_FieldOperationMetadata_IndexConfigDelta.Size(m)
}
func (m *FieldOperationMetadata_IndexConfigDelta) XXX_DiscardUnknown() {
	xxx_messageInfo_FieldOperationMetadata_IndexConfigDelta.DiscardUnknown(m)
}

var xxx_messageInfo_FieldOperationMetadata_IndexConfigDelta proto.InternalMessageInfo

func (m *FieldOperationMetadata_IndexConfigDelta) GetChangeType() FieldOperationMetadata_IndexConfigDelta_ChangeType {
	if m != nil {
		return m.ChangeType
	}
	return FieldOperationMetadata_IndexConfigDelta_CHANGE_TYPE_UNSPECIFIED
}

func (m *FieldOperationMetadata_IndexConfigDelta) GetIndex() *Index {
	if m != nil {
		return m.Index
	}
	return nil
}

// Metadata for [google.longrunning.Operation][google.longrunning.Operation] results from
// [FirestoreAdmin.ExportDocuments][google.firestore.admin.v1.FirestoreAdmin.ExportDocuments].
type ExportDocumentsMetadata struct {
	// The time this operation started.
	StartTime *timestamp.Timestamp `protobuf:"bytes,1,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty"`
	// The time this operation completed. Will be unset if operation still in
	// progress.
	EndTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=end_time,json=endTime,proto3" json:"end_time,omitempty"`
	// The state of the export operation.
	OperationState OperationState `protobuf:"varint,3,opt,name=operation_state,json=operationState,proto3,enum=google.firestore.admin.v1.OperationState" json:"operation_state,omitempty"`
	// The progress, in documents, of this operation.
	ProgressDocuments *Progress `protobuf:"bytes,4,opt,name=progress_documents,json=progressDocuments,proto3" json:"progress_documents,omitempty"`
	// The progress, in bytes, of this operation.
	ProgressBytes *Progress `protobuf:"bytes,5,opt,name=progress_bytes,json=progressBytes,proto3" json:"progress_bytes,omitempty"`
	// Which collection ids are being exported.
	CollectionIds []string `protobuf:"bytes,6,rep,name=collection_ids,json=collectionIds,proto3" json:"collection_ids,omitempty"`
	// Where the entities are being exported to.
	OutputUriPrefix      string   `protobuf:"bytes,7,opt,name=output_uri_prefix,json=outputUriPrefix,proto3" json:"output_uri_prefix,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ExportDocumentsMetadata) Reset()         { *m = ExportDocumentsMetadata{} }
func (m *ExportDocumentsMetadata) String() string { return proto.CompactTextString(m) }
func (*ExportDocumentsMetadata) ProtoMessage()    {}
func (*ExportDocumentsMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_f3b79aaf4866e7e0, []int{2}
}

func (m *ExportDocumentsMetadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExportDocumentsMetadata.Unmarshal(m, b)
}
func (m *ExportDocumentsMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExportDocumentsMetadata.Marshal(b, m, deterministic)
}
func (m *ExportDocumentsMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExportDocumentsMetadata.Merge(m, src)
}
func (m *ExportDocumentsMetadata) XXX_Size() int {
	return xxx_messageInfo_ExportDocumentsMetadata.Size(m)
}
func (m *ExportDocumentsMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_ExportDocumentsMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_ExportDocumentsMetadata proto.InternalMessageInfo

func (m *ExportDocumentsMetadata) GetStartTime() *timestamp.Timestamp {
	if m != nil {
		return m.StartTime
	}
	return nil
}

func (m *ExportDocumentsMetadata) GetEndTime() *timestamp.Timestamp {
	if m != nil {
		return m.EndTime
	}
	return nil
}

func (m *ExportDocumentsMetadata) GetOperationState() OperationState {
	if m != nil {
		return m.OperationState
	}
	return OperationState_OPERATION_STATE_UNSPECIFIED
}

func (m *ExportDocumentsMetadata) GetProgressDocuments() *Progress {
	if m != nil {
		return m.ProgressDocuments
	}
	return nil
}

func (m *ExportDocumentsMetadata) GetProgressBytes() *Progress {
	if m != nil {
		return m.ProgressBytes
	}
	return nil
}

func (m *ExportDocumentsMetadata) GetCollectionIds() []string {
	if m != nil {
		return m.CollectionIds
	}
	return nil
}

func (m *ExportDocumentsMetadata) GetOutputUriPrefix() string {
	if m != nil {
		return m.OutputUriPrefix
	}
	return ""
}

// Metadata for [google.longrunning.Operation][google.longrunning.Operation] results from
// [FirestoreAdmin.ImportDocuments][google.firestore.admin.v1.FirestoreAdmin.ImportDocuments].
type ImportDocumentsMetadata struct {
	// The time this operation started.
	StartTime *timestamp.Timestamp `protobuf:"bytes,1,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty"`
	// The time this operation completed. Will be unset if operation still in
	// progress.
	EndTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=end_time,json=endTime,proto3" json:"end_time,omitempty"`
	// The state of the import operation.
	OperationState OperationState `protobuf:"varint,3,opt,name=operation_state,json=operationState,proto3,enum=google.firestore.admin.v1.OperationState" json:"operation_state,omitempty"`
	// The progress, in documents, of this operation.
	ProgressDocuments *Progress `protobuf:"bytes,4,opt,name=progress_documents,json=progressDocuments,proto3" json:"progress_documents,omitempty"`
	// The progress, in bytes, of this operation.
	ProgressBytes *Progress `protobuf:"bytes,5,opt,name=progress_bytes,json=progressBytes,proto3" json:"progress_bytes,omitempty"`
	// Which collection ids are being imported.
	CollectionIds []string `protobuf:"bytes,6,rep,name=collection_ids,json=collectionIds,proto3" json:"collection_ids,omitempty"`
	// The location of the documents being imported.
	InputUriPrefix       string   `protobuf:"bytes,7,opt,name=input_uri_prefix,json=inputUriPrefix,proto3" json:"input_uri_prefix,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ImportDocumentsMetadata) Reset()         { *m = ImportDocumentsMetadata{} }
func (m *ImportDocumentsMetadata) String() string { return proto.CompactTextString(m) }
func (*ImportDocumentsMetadata) ProtoMessage()    {}
func (*ImportDocumentsMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_f3b79aaf4866e7e0, []int{3}
}

func (m *ImportDocumentsMetadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ImportDocumentsMetadata.Unmarshal(m, b)
}
func (m *ImportDocumentsMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ImportDocumentsMetadata.Marshal(b, m, deterministic)
}
func (m *ImportDocumentsMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ImportDocumentsMetadata.Merge(m, src)
}
func (m *ImportDocumentsMetadata) XXX_Size() int {
	return xxx_messageInfo_ImportDocumentsMetadata.Size(m)
}
func (m *ImportDocumentsMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_ImportDocumentsMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_ImportDocumentsMetadata proto.InternalMessageInfo

func (m *ImportDocumentsMetadata) GetStartTime() *timestamp.Timestamp {
	if m != nil {
		return m.StartTime
	}
	return nil
}

func (m *ImportDocumentsMetadata) GetEndTime() *timestamp.Timestamp {
	if m != nil {
		return m.EndTime
	}
	return nil
}

func (m *ImportDocumentsMetadata) GetOperationState() OperationState {
	if m != nil {
		return m.OperationState
	}
	return OperationState_OPERATION_STATE_UNSPECIFIED
}

func (m *ImportDocumentsMetadata) GetProgressDocuments() *Progress {
	if m != nil {
		return m.ProgressDocuments
	}
	return nil
}

func (m *ImportDocumentsMetadata) GetProgressBytes() *Progress {
	if m != nil {
		return m.ProgressBytes
	}
	return nil
}

func (m *ImportDocumentsMetadata) GetCollectionIds() []string {
	if m != nil {
		return m.CollectionIds
	}
	return nil
}

func (m *ImportDocumentsMetadata) GetInputUriPrefix() string {
	if m != nil {
		return m.InputUriPrefix
	}
	return ""
}

// Returned in the [google.longrunning.Operation][google.longrunning.Operation] response field.
type ExportDocumentsResponse struct {
	// Location of the output files. This can be used to begin an import
	// into Cloud Firestore (this project or another project) after the operation
	// completes successfully.
	OutputUriPrefix      string   `protobuf:"bytes,1,opt,name=output_uri_prefix,json=outputUriPrefix,proto3" json:"output_uri_prefix,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ExportDocumentsResponse) Reset()         { *m = ExportDocumentsResponse{} }
func (m *ExportDocumentsResponse) String() string { return proto.CompactTextString(m) }
func (*ExportDocumentsResponse) ProtoMessage()    {}
func (*ExportDocumentsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_f3b79aaf4866e7e0, []int{4}
}

func (m *ExportDocumentsResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExportDocumentsResponse.Unmarshal(m, b)
}
func (m *ExportDocumentsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExportDocumentsResponse.Marshal(b, m, deterministic)
}
func (m *ExportDocumentsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExportDocumentsResponse.Merge(m, src)
}
func (m *ExportDocumentsResponse) XXX_Size() int {
	return xxx_messageInfo_ExportDocumentsResponse.Size(m)
}
func (m *ExportDocumentsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ExportDocumentsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ExportDocumentsResponse proto.InternalMessageInfo

func (m *ExportDocumentsResponse) GetOutputUriPrefix() string {
	if m != nil {
		return m.OutputUriPrefix
	}
	return ""
}

// Describes the progress of the operation.
// Unit of work is generic and must be interpreted based on where [Progress][google.firestore.admin.v1.Progress]
// is used.
type Progress struct {
	// The amount of work estimated.
	EstimatedWork int64 `protobuf:"varint,1,opt,name=estimated_work,json=estimatedWork,proto3" json:"estimated_work,omitempty"`
	// The amount of work completed.
	CompletedWork        int64    `protobuf:"varint,2,opt,name=completed_work,json=completedWork,proto3" json:"completed_work,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Progress) Reset()         { *m = Progress{} }
func (m *Progress) String() string { return proto.CompactTextString(m) }
func (*Progress) ProtoMessage()    {}
func (*Progress) Descriptor() ([]byte, []int) {
	return fileDescriptor_f3b79aaf4866e7e0, []int{5}
}

func (m *Progress) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Progress.Unmarshal(m, b)
}
func (m *Progress) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Progress.Marshal(b, m, deterministic)
}
func (m *Progress) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Progress.Merge(m, src)
}
func (m *Progress) XXX_Size() int {
	return xxx_messageInfo_Progress.Size(m)
}
func (m *Progress) XXX_DiscardUnknown() {
	xxx_messageInfo_Progress.DiscardUnknown(m)
}

var xxx_messageInfo_Progress proto.InternalMessageInfo

func (m *Progress) GetEstimatedWork() int64 {
	if m != nil {
		return m.EstimatedWork
	}
	return 0
}

func (m *Progress) GetCompletedWork() int64 {
	if m != nil {
		return m.CompletedWork
	}
	return 0
}

func init() {
	proto.RegisterEnum("google.firestore.admin.v1.OperationState", OperationState_name, OperationState_value)
	proto.RegisterEnum("google.firestore.admin.v1.FieldOperationMetadata_IndexConfigDelta_ChangeType", FieldOperationMetadata_IndexConfigDelta_ChangeType_name, FieldOperationMetadata_IndexConfigDelta_ChangeType_value)
	proto.RegisterType((*IndexOperationMetadata)(nil), "google.firestore.admin.v1.IndexOperationMetadata")
	proto.RegisterType((*FieldOperationMetadata)(nil), "google.firestore.admin.v1.FieldOperationMetadata")
	proto.RegisterType((*FieldOperationMetadata_IndexConfigDelta)(nil), "google.firestore.admin.v1.FieldOperationMetadata.IndexConfigDelta")
	proto.RegisterType((*ExportDocumentsMetadata)(nil), "google.firestore.admin.v1.ExportDocumentsMetadata")
	proto.RegisterType((*ImportDocumentsMetadata)(nil), "google.firestore.admin.v1.ImportDocumentsMetadata")
	proto.RegisterType((*ExportDocumentsResponse)(nil), "google.firestore.admin.v1.ExportDocumentsResponse")
	proto.RegisterType((*Progress)(nil), "google.firestore.admin.v1.Progress")
}

func init() {
	proto.RegisterFile("google/firestore/admin/v1/operation.proto", fileDescriptor_f3b79aaf4866e7e0)
}

var fileDescriptor_f3b79aaf4866e7e0 = []byte{
	// 850 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xec, 0x56, 0x4f, 0x6f, 0xe3, 0x44,
	0x1c, 0xc5, 0x71, 0x92, 0x6e, 0x7e, 0xa5, 0x59, 0x77, 0x40, 0xdb, 0xd0, 0x05, 0x35, 0x0a, 0x5a,
	0x29, 0xbb, 0x07, 0x47, 0x2d, 0x02, 0x09, 0x21, 0x2d, 0x4a, 0x1d, 0xa7, 0x18, 0xa5, 0x89, 0xe5,
	0xa4, 0x05, 0x56, 0x95, 0x2c, 0x37, 0x9e, 0x98, 0xd1, 0xda, 0x1e, 0xcb, 0x33, 0x59, 0xda, 0x23,
	0x5f, 0x84, 0x03, 0x47, 0x3e, 0x03, 0x9f, 0x80, 0x13, 0xe2, 0xa3, 0x70, 0xe4, 0x84, 0x66, 0xfc,
	0x27, 0xda, 0x92, 0x14, 0x58, 0x2a, 0xb1, 0x87, 0xbd, 0xe5, 0x37, 0x7e, 0xef, 0xfd, 0x7e, 0x33,
	0xef, 0xcd, 0x28, 0xf0, 0x38, 0xa0, 0x34, 0x08, 0x71, 0x6f, 0x41, 0x52, 0xcc, 0x38, 0x4d, 0x71,
	0xcf, 0xf3, 0x23, 0x12, 0xf7, 0x5e, 0x1c, 0xf6, 0x68, 0x82, 0x53, 0x8f, 0x13, 0x1a, 0xeb, 0x49,
	0x4a, 0x39, 0x45, 0xef, 0x65, 0x50, 0xbd, 0x84, 0xea, 0x12, 0xaa, 0xbf, 0x38, 0xdc, 0x7f, 0xb4,
	0x59, 0x85, 0xc4, 0x3e, 0xbe, 0xca, 0x14, 0xf6, 0x0f, 0x72, 0x98, 0xac, 0x2e, 0x97, 0x8b, 0x1e,
	0x27, 0x11, 0x66, 0xdc, 0x8b, 0x92, 0x1c, 0xf0, 0x7e, 0x0e, 0xf0, 0x12, 0xd2, 0xf3, 0xe2, 0x98,
	0x72, 0xd9, 0x9f, 0x65, 0x5f, 0x3b, 0xdf, 0xab, 0xf0, 0xc0, 0x12, 0x72, 0x93, 0x62, 0xb2, 0x53,
	0xcc, 0x3d, 0xdf, 0xe3, 0x1e, 0xfa, 0x14, 0x80, 0x71, 0x2f, 0xe5, 0xae, 0x50, 0x6c, 0x29, 0x6d,
	0xa5, 0xbb, 0x7d, 0xb4, 0xaf, 0xe7, 0x03, 0x17, 0xed, 0xf4, 0x59, 0xd1, 0xce, 0x69, 0x48, 0xb4,
	0xa8, 0xd1, 0xc7, 0x70, 0x0f, 0xc7, 0x7e, 0x46, 0xac, 0xfc, 0x2d, 0x71, 0x0b, 0xc7, 0xbe, 0xa4,
	0xbd, 0x0b, 0x35, 0xb9, 0xb5, 0x96, 0xda, 0x56, 0xba, 0x0d, 0x27, 0x2b, 0xd0, 0xe7, 0x50, 0x63,
	0xdc, 0xe3, 0xb8, 0x55, 0x6d, 0x2b, 0xdd, 0xe6, 0xd1, 0x63, 0x7d, 0xe3, 0x99, 0xe9, 0xe5, 0x26,
	0xa6, 0x82, 0xe0, 0x64, 0x3c, 0xe4, 0x00, 0x4a, 0x52, 0x1a, 0xa4, 0x98, 0x31, 0xd7, 0xa7, 0xf3,
	0x65, 0x84, 0x63, 0xce, 0x5a, 0x35, 0x39, 0xd7, 0x87, 0xb7, 0xa8, 0xd9, 0x39, 0xc9, 0xd9, 0x2d,
	0xe8, 0x83, 0x82, 0x8d, 0xbe, 0x84, 0x66, 0xa9, 0x79, 0x79, 0xcd, 0x31, 0x6b, 0xd5, 0xff, 0xb9,
	0xde, 0x4e, 0x41, 0x3d, 0x16, 0xcc, 0xce, 0xef, 0x35, 0x78, 0x30, 0x24, 0x38, 0xf4, 0x5f, 0x13,
	0x0f, 0x16, 0x62, 0x96, 0xc2, 0x03, 0x59, 0xa0, 0x14, 0xde, 0x91, 0x66, 0xb8, 0x73, 0x1a, 0x2f,
	0x48, 0xe0, 0xfa, 0x38, 0xe4, 0x1e, 0x6b, 0x55, 0xdb, 0x6a, 0x77, 0xfb, 0xe8, 0xf8, 0x96, 0x3d,
	0xaf, 0xdf, 0x97, 0x2e, 0x23, 0x67, 0x48, 0xad, 0x81, 0x90, 0x72, 0x76, 0xc9, 0x8d, 0x15, 0xb6,
	0xf2, 0xbd, 0x76, 0xa7, 0xbe, 0xd7, 0xef, 0xd8, 0xf7, 0xad, 0x57, 0xf5, 0x7d, 0xff, 0x0f, 0x05,
	0xb4, 0x9b, 0x07, 0x81, 0x62, 0xd8, 0x9e, 0x7f, 0xeb, 0xc5, 0x01, 0x76, 0xf9, 0x75, 0x92, 0x59,
	0xde, 0x3c, 0x3a, 0xfd, 0xef, 0x27, 0xac, 0x1b, 0x52, 0x75, 0x76, 0x9d, 0x60, 0x07, 0xe6, 0xe5,
	0x6f, 0xf4, 0x49, 0x71, 0xe7, 0xb2, 0x8c, 0xb4, 0x6f, 0xe9, 0x24, 0x25, 0xf3, 0x5b, 0xd9, 0x79,
	0x0a, 0xb0, 0x52, 0x44, 0x0f, 0x61, 0xcf, 0xf8, 0xa2, 0x3f, 0x3e, 0x31, 0xdd, 0xd9, 0x37, 0xb6,
	0xe9, 0x9e, 0x8d, 0xa7, 0xb6, 0x69, 0x58, 0x43, 0xcb, 0x1c, 0x68, 0x6f, 0xa1, 0x2d, 0x50, 0xfb,
	0x83, 0x81, 0xa6, 0x20, 0x80, 0xba, 0x63, 0x9e, 0x4e, 0xce, 0x4d, 0xad, 0xd2, 0xf9, 0x4d, 0x85,
	0x3d, 0xf3, 0x2a, 0xa1, 0x29, 0x2f, 0x0f, 0xf7, 0x7f, 0x4c, 0xbd, 0x03, 0xf7, 0xcb, 0xa7, 0xd9,
	0xcd, 0x52, 0xa7, 0xfe, 0xdb, 0xd4, 0x35, 0xe9, 0x4b, 0xf5, 0x86, 0xf8, 0x55, 0xef, 0x38, 0x7e,
	0xb5, 0x57, 0x8d, 0x1f, 0x7a, 0x04, 0xcd, 0x39, 0x0d, 0x43, 0x3c, 0x97, 0x9b, 0x26, 0xbe, 0xb8,
	0x1a, 0x6a, 0xb7, 0xe1, 0xec, 0xac, 0x56, 0x2d, 0x9f, 0xa1, 0x27, 0xb0, 0x4b, 0x97, 0x3c, 0x59,
	0x72, 0x77, 0x99, 0x12, 0x37, 0x49, 0xf1, 0x82, 0x5c, 0xc9, 0xd0, 0x37, 0x9c, 0xfb, 0xd9, 0x87,
	0xb3, 0x94, 0xd8, 0x72, 0xb9, 0xf3, 0xab, 0x0a, 0x7b, 0x56, 0xf4, 0xc6, 0xd4, 0xd7, 0xde, 0xd4,
	0x2e, 0x68, 0x24, 0x5e, 0xeb, 0x69, 0x53, 0xae, 0xaf, 0x2c, 0x35, 0xff, 0x72, 0x4d, 0x1d, 0xcc,
	0x12, 0x1a, 0x33, 0xbc, 0x3e, 0x19, 0xca, 0xfa, 0x64, 0x7c, 0x0d, 0xf7, 0x8a, 0x91, 0xc5, 0x8c,
	0x98, 0x71, 0x12, 0x79, 0x1c, 0xfb, 0xee, 0x77, 0x34, 0x7d, 0x2e, 0x49, 0xaa, 0xb3, 0x53, 0xae,
	0x7e, 0x45, 0xd3, 0xe7, 0xd9, 0x56, 0xa2, 0x24, 0xc4, 0x25, 0xac, 0x92, 0xc1, 0xca, 0x55, 0x01,
	0x7b, 0xf2, 0x83, 0x02, 0xcd, 0x97, 0x4d, 0x43, 0x07, 0xf0, 0x70, 0x62, 0x9b, 0x4e, 0x7f, 0x66,
	0x4d, 0xc6, 0xee, 0x74, 0xd6, 0x9f, 0xdd, 0x7c, 0x91, 0x34, 0x78, 0xdb, 0x1a, 0x5b, 0x33, 0xab,
	0x3f, 0xb2, 0x9e, 0x59, 0xe3, 0x13, 0x4d, 0x41, 0x4d, 0x00, 0xdb, 0x99, 0x18, 0xe6, 0x74, 0x2a,
	0xea, 0x8a, 0xa8, 0x8d, 0xfe, 0xd8, 0x30, 0x47, 0x23, 0x51, 0xab, 0xa2, 0x1e, 0x5a, 0xe3, 0x02,
	0x5f, 0x15, 0xf5, 0xf4, 0xcc, 0x10, 0xf8, 0xe1, 0xd9, 0x48, 0xab, 0x89, 0xa7, 0x6d, 0xd8, 0xb7,
	0x46, 0xe6, 0x40, 0xab, 0xa3, 0x1d, 0x68, 0xe4, 0x5c, 0x73, 0xa0, 0x6d, 0x1d, 0xff, 0xac, 0xc0,
	0x07, 0x73, 0x1a, 0x6d, 0x36, 0xf3, 0x78, 0x35, 0xbf, 0x2d, 0xe2, 0x6c, 0x2b, 0xcf, 0x9e, 0xe6,
	0xe0, 0x80, 0x86, 0x5e, 0x1c, 0xe8, 0x34, 0x0d, 0x7a, 0x01, 0x8e, 0x65, 0xd8, 0x7b, 0xd9, 0x27,
	0x2f, 0x21, 0x6c, 0xcd, 0x7f, 0xc3, 0xcf, 0xe4, 0x8f, 0x1f, 0x2b, 0xd5, 0x13, 0x63, 0x38, 0xfd,
	0xa9, 0x72, 0x70, 0x92, 0xe9, 0x18, 0x21, 0x5d, 0xfa, 0xfa, 0xb0, 0x6c, 0xdd, 0x97, 0xad, 0xcf,
	0x0f, 0x7f, 0x29, 0x10, 0x17, 0x12, 0x71, 0x51, 0x22, 0x2e, 0x24, 0xe2, 0xe2, 0xfc, 0xf0, 0xb2,
	0x2e, 0xbb, 0x7e, 0xf4, 0x67, 0x00, 0x00, 0x00, 0xff, 0xff, 0x63, 0x18, 0x66, 0xe2, 0xd6, 0x0a,
	0x00, 0x00,
}
