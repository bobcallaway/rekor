//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.12.4
// source: rekor_log.proto

package protobuf

import (
	empty "github.com/golang/protobuf/ptypes/empty"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type LogInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The information about the currently active shard
	CurrentShardInfo *LogShardInfo `protobuf:"bytes,1,opt,name=current_shard_info,json=currentShardInfo,proto3" json:"current_shard_info,omitempty"`
	//
	// The information about inactive (previous) shards
	InactiveShardInfo []*LogShardInfo `protobuf:"bytes,2,rep,name=inactive_shard_info,json=inactiveShardInfo,proto3" json:"inactive_shard_info,omitempty"`
}

func (x *LogInfo) Reset() {
	*x = LogInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rekor_log_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogInfo) ProtoMessage() {}

func (x *LogInfo) ProtoReflect() protoreflect.Message {
	mi := &file_rekor_log_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogInfo.ProtoReflect.Descriptor instead.
func (*LogInfo) Descriptor() ([]byte, []int) {
	return file_rekor_log_proto_rawDescGZIP(), []int{0}
}

func (x *LogInfo) GetCurrentShardInfo() *LogShardInfo {
	if x != nil {
		return x.CurrentShardInfo
	}
	return nil
}

func (x *LogInfo) GetInactiveShardInfo() []*LogShardInfo {
	if x != nil {
		return x.InactiveShardInfo
	}
	return nil
}

type TreeID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The ID of the tree
	Id int64 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *TreeID) Reset() {
	*x = TreeID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rekor_log_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TreeID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TreeID) ProtoMessage() {}

func (x *TreeID) ProtoReflect() protoreflect.Message {
	mi := &file_rekor_log_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TreeID.ProtoReflect.Descriptor instead.
func (*TreeID) Descriptor() ([]byte, []int) {
	return file_rekor_log_proto_rawDescGZIP(), []int{1}
}

func (x *TreeID) GetId() int64 {
	if x != nil {
		return x.Id
	}
	return 0
}

type LogShardInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The current hash value stored at the root of the merkle tree
	RootHash string `protobuf:"bytes,1,opt,name=root_hash,json=rootHash,proto3" json:"root_hash,omitempty"`
	//
	// The current number of nodes in the merkle tree
	TreeSize int64 `protobuf:"varint,2,opt,name=tree_size,json=treeSize,proto3" json:"tree_size,omitempty"`
	//
	// The current signed tree head
	SignedTreeHead []byte `protobuf:"bytes,3,opt,name=signed_tree_head,json=signedTreeHead,proto3" json:"signed_tree_head,omitempty"`
	//
	// The tree ID
	TreeId *TreeID `protobuf:"bytes,4,opt,name=tree_id,json=treeId,proto3" json:"tree_id,omitempty"`
}

func (x *LogShardInfo) Reset() {
	*x = LogShardInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rekor_log_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogShardInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogShardInfo) ProtoMessage() {}

func (x *LogShardInfo) ProtoReflect() protoreflect.Message {
	mi := &file_rekor_log_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogShardInfo.ProtoReflect.Descriptor instead.
func (*LogShardInfo) Descriptor() ([]byte, []int) {
	return file_rekor_log_proto_rawDescGZIP(), []int{2}
}

func (x *LogShardInfo) GetRootHash() string {
	if x != nil {
		return x.RootHash
	}
	return ""
}

func (x *LogShardInfo) GetTreeSize() int64 {
	if x != nil {
		return x.TreeSize
	}
	return 0
}

func (x *LogShardInfo) GetSignedTreeHead() []byte {
	if x != nil {
		return x.SignedTreeHead
	}
	return nil
}

func (x *LogShardInfo) GetTreeId() *TreeID {
	if x != nil {
		return x.TreeId
	}
	return nil
}

type GetLogPublicKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The ID of the tree you wish to get a public key for
	TreeId *TreeID `protobuf:"bytes,1,opt,name=tree_id,json=treeId,proto3" json:"tree_id,omitempty"`
}

func (x *GetLogPublicKeyRequest) Reset() {
	*x = GetLogPublicKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rekor_log_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetLogPublicKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetLogPublicKeyRequest) ProtoMessage() {}

func (x *GetLogPublicKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rekor_log_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetLogPublicKeyRequest.ProtoReflect.Descriptor instead.
func (*GetLogPublicKeyRequest) Descriptor() ([]byte, []int) {
	return file_rekor_log_proto_rawDescGZIP(), []int{3}
}

func (x *GetLogPublicKeyRequest) GetTreeId() *TreeID {
	if x != nil {
		return x.TreeId
	}
	return nil
}

type LogPublicKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// PEM encoded public key
	Content string `protobuf:"bytes,1,opt,name=content,proto3" json:"content,omitempty"`
}

func (x *LogPublicKey) Reset() {
	*x = LogPublicKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rekor_log_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogPublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogPublicKey) ProtoMessage() {}

func (x *LogPublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_rekor_log_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogPublicKey.ProtoReflect.Descriptor instead.
func (*LogPublicKey) Descriptor() ([]byte, []int) {
	return file_rekor_log_proto_rawDescGZIP(), []int{4}
}

func (x *LogPublicKey) GetContent() string {
	if x != nil {
		return x.Content
	}
	return ""
}

type GetConsistencyProofRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The ID of the tree you wish to get a consistency proof for
	// (defaults to the current tree if not specified)
	TreeId *TreeID `protobuf:"bytes,1,opt,name=tree_id,json=treeId,proto3" json:"tree_id,omitempty"`
	//
	// The size of the tree that you wish to prove consistency from
	// (1 means the beginning of the log)
	StartSize int64 `protobuf:"varint,2,opt,name=start_size,json=startSize,proto3" json:"start_size,omitempty"` // TODO: set minimum and default to 1
	//
	// The size of the tree that you wish to prove consistency to
	// (defaults to the current size of the tree)
	EndSize int64 `protobuf:"varint,3,opt,name=end_size,json=endSize,proto3" json:"end_size,omitempty"` // TODO: set minimum
}

func (x *GetConsistencyProofRequest) Reset() {
	*x = GetConsistencyProofRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rekor_log_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetConsistencyProofRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetConsistencyProofRequest) ProtoMessage() {}

func (x *GetConsistencyProofRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rekor_log_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetConsistencyProofRequest.ProtoReflect.Descriptor instead.
func (*GetConsistencyProofRequest) Descriptor() ([]byte, []int) {
	return file_rekor_log_proto_rawDescGZIP(), []int{5}
}

func (x *GetConsistencyProofRequest) GetTreeId() *TreeID {
	if x != nil {
		return x.TreeId
	}
	return nil
}

func (x *GetConsistencyProofRequest) GetStartSize() int64 {
	if x != nil {
		return x.StartSize
	}
	return 0
}

func (x *GetConsistencyProofRequest) GetEndSize() int64 {
	if x != nil {
		return x.EndSize
	}
	return 0
}

type ConsistencyProof struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The hash value stored at the root of the merkle tree at the time the proof was generated
	RootHash string `protobuf:"bytes,1,opt,name=root_hash,json=rootHash,proto3" json:"root_hash,omitempty"`
	//
	// One or more hash values that can be combined to calculate a consistency proof
	Hashes []string `protobuf:"bytes,2,rep,name=hashes,proto3" json:"hashes,omitempty"`
}

func (x *ConsistencyProof) Reset() {
	*x = ConsistencyProof{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rekor_log_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConsistencyProof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConsistencyProof) ProtoMessage() {}

func (x *ConsistencyProof) ProtoReflect() protoreflect.Message {
	mi := &file_rekor_log_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConsistencyProof.ProtoReflect.Descriptor instead.
func (*ConsistencyProof) Descriptor() ([]byte, []int) {
	return file_rekor_log_proto_rawDescGZIP(), []int{6}
}

func (x *ConsistencyProof) GetRootHash() string {
	if x != nil {
		return x.RootHash
	}
	return ""
}

func (x *ConsistencyProof) GetHashes() []string {
	if x != nil {
		return x.Hashes
	}
	return nil
}

var File_rekor_log_proto protoreflect.FileDescriptor

var file_rekor_log_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x5f, 0x6c, 0x6f, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x15, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e,
	0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f,
	0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb1, 0x01, 0x0a, 0x07, 0x4c, 0x6f, 0x67, 0x49, 0x6e, 0x66, 0x6f,
	0x12, 0x51, 0x0a, 0x12, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x68, 0x61, 0x72,
	0x64, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x64,
	0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f,
	0x72, 0x2e, 0x76, 0x32, 0x2e, 0x4c, 0x6f, 0x67, 0x53, 0x68, 0x61, 0x72, 0x64, 0x49, 0x6e, 0x66,
	0x6f, 0x52, 0x10, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x53, 0x68, 0x61, 0x72, 0x64, 0x49,
	0x6e, 0x66, 0x6f, 0x12, 0x53, 0x0a, 0x13, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x5f,
	0x73, 0x68, 0x61, 0x72, 0x64, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x23, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e,
	0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x4c, 0x6f, 0x67, 0x53, 0x68, 0x61, 0x72,
	0x64, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x11, 0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x53,
	0x68, 0x61, 0x72, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x22, 0x18, 0x0a, 0x06, 0x54, 0x72, 0x65, 0x65,
	0x49, 0x44, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x02,
	0x69, 0x64, 0x22, 0xaa, 0x01, 0x0a, 0x0c, 0x4c, 0x6f, 0x67, 0x53, 0x68, 0x61, 0x72, 0x64, 0x49,
	0x6e, 0x66, 0x6f, 0x12, 0x1b, 0x0a, 0x09, 0x72, 0x6f, 0x6f, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x72, 0x6f, 0x6f, 0x74, 0x48, 0x61, 0x73, 0x68,
	0x12, 0x1b, 0x0a, 0x09, 0x74, 0x72, 0x65, 0x65, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x08, 0x74, 0x72, 0x65, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x28, 0x0a,
	0x10, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f, 0x74, 0x72, 0x65, 0x65, 0x5f, 0x68, 0x65, 0x61,
	0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x54,
	0x72, 0x65, 0x65, 0x48, 0x65, 0x61, 0x64, 0x12, 0x36, 0x0a, 0x07, 0x74, 0x72, 0x65, 0x65, 0x5f,
	0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73,
	0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32,
	0x2e, 0x54, 0x72, 0x65, 0x65, 0x49, 0x44, 0x52, 0x06, 0x74, 0x72, 0x65, 0x65, 0x49, 0x64, 0x22,
	0x55, 0x0a, 0x16, 0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b,
	0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3b, 0x0a, 0x07, 0x74, 0x72, 0x65,
	0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x64, 0x65, 0x76,
	0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e,
	0x76, 0x32, 0x2e, 0x54, 0x72, 0x65, 0x65, 0x49, 0x44, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x06,
	0x74, 0x72, 0x65, 0x65, 0x49, 0x64, 0x22, 0x28, 0x0a, 0x0c, 0x4c, 0x6f, 0x67, 0x50, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x22, 0x93, 0x01, 0x0a, 0x1a, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65,
	0x6e, 0x63, 0x79, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x36, 0x0a, 0x07, 0x74, 0x72, 0x65, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1d, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e,
	0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x54, 0x72, 0x65, 0x65, 0x49, 0x44, 0x52,
	0x06, 0x74, 0x72, 0x65, 0x65, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74,
	0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x73, 0x74, 0x61,
	0x72, 0x74, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x1e, 0x0a, 0x08, 0x65, 0x6e, 0x64, 0x5f, 0x73, 0x69,
	0x7a, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x07, 0x65,
	0x6e, 0x64, 0x53, 0x69, 0x7a, 0x65, 0x22, 0x47, 0x0a, 0x10, 0x43, 0x6f, 0x6e, 0x73, 0x69, 0x73,
	0x74, 0x65, 0x6e, 0x63, 0x79, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x1b, 0x0a, 0x09, 0x72, 0x6f,
	0x6f, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x72,
	0x6f, 0x6f, 0x74, 0x48, 0x61, 0x73, 0x68, 0x12, 0x16, 0x0a, 0x06, 0x68, 0x61, 0x73, 0x68, 0x65,
	0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x68, 0x61, 0x73, 0x68, 0x65, 0x73, 0x32,
	0xf6, 0x02, 0x0a, 0x03, 0x4c, 0x6f, 0x67, 0x12, 0x59, 0x0a, 0x0a, 0x47, 0x65, 0x74, 0x4c, 0x6f,
	0x67, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x1e, 0x2e,
	0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b,
	0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x4c, 0x6f, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x22, 0x13, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x0d, 0x12, 0x0b, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f, 0x6c,
	0x6f, 0x67, 0x12, 0x84, 0x01, 0x0a, 0x0f, 0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x50, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x2d, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x47,
	0x65, 0x74, 0x4c, 0x6f, 0x67, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x23, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73,
	0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x4c, 0x6f,
	0x67, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x22, 0x1d, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x17, 0x22, 0x15, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f, 0x6c, 0x6f, 0x67, 0x2f,
	0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x8c, 0x01, 0x0a, 0x13, 0x47, 0x65,
	0x74, 0x43, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x50, 0x72, 0x6f, 0x6f,
	0x66, 0x12, 0x31, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65,
	0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e,
	0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x27, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74,
	0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x43, 0x6f, 0x6e,
	0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x19, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x13, 0x22, 0x11, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f, 0x6c,
	0x6f, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x42, 0x5a, 0x0a, 0x15, 0x64, 0x65, 0x76, 0x2e,
	0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76,
	0x32, 0x42, 0x0d, 0x52, 0x65, 0x6b, 0x6f, 0x72, 0x4c, 0x6f, 0x67, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x50, 0x01, 0x5a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73,
	0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2f, 0x70, 0x6b,
	0x67, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rekor_log_proto_rawDescOnce sync.Once
	file_rekor_log_proto_rawDescData = file_rekor_log_proto_rawDesc
)

func file_rekor_log_proto_rawDescGZIP() []byte {
	file_rekor_log_proto_rawDescOnce.Do(func() {
		file_rekor_log_proto_rawDescData = protoimpl.X.CompressGZIP(file_rekor_log_proto_rawDescData)
	})
	return file_rekor_log_proto_rawDescData
}

var file_rekor_log_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_rekor_log_proto_goTypes = []interface{}{
	(*LogInfo)(nil),                    // 0: dev.sigstore.rekor.v2.LogInfo
	(*TreeID)(nil),                     // 1: dev.sigstore.rekor.v2.TreeID
	(*LogShardInfo)(nil),               // 2: dev.sigstore.rekor.v2.LogShardInfo
	(*GetLogPublicKeyRequest)(nil),     // 3: dev.sigstore.rekor.v2.GetLogPublicKeyRequest
	(*LogPublicKey)(nil),               // 4: dev.sigstore.rekor.v2.LogPublicKey
	(*GetConsistencyProofRequest)(nil), // 5: dev.sigstore.rekor.v2.GetConsistencyProofRequest
	(*ConsistencyProof)(nil),           // 6: dev.sigstore.rekor.v2.ConsistencyProof
	(*empty.Empty)(nil),                // 7: google.protobuf.Empty
}
var file_rekor_log_proto_depIdxs = []int32{
	2, // 0: dev.sigstore.rekor.v2.LogInfo.current_shard_info:type_name -> dev.sigstore.rekor.v2.LogShardInfo
	2, // 1: dev.sigstore.rekor.v2.LogInfo.inactive_shard_info:type_name -> dev.sigstore.rekor.v2.LogShardInfo
	1, // 2: dev.sigstore.rekor.v2.LogShardInfo.tree_id:type_name -> dev.sigstore.rekor.v2.TreeID
	1, // 3: dev.sigstore.rekor.v2.GetLogPublicKeyRequest.tree_id:type_name -> dev.sigstore.rekor.v2.TreeID
	1, // 4: dev.sigstore.rekor.v2.GetConsistencyProofRequest.tree_id:type_name -> dev.sigstore.rekor.v2.TreeID
	7, // 5: dev.sigstore.rekor.v2.Log.GetLogInfo:input_type -> google.protobuf.Empty
	3, // 6: dev.sigstore.rekor.v2.Log.GetLogPublicKey:input_type -> dev.sigstore.rekor.v2.GetLogPublicKeyRequest
	5, // 7: dev.sigstore.rekor.v2.Log.GetConsistencyProof:input_type -> dev.sigstore.rekor.v2.GetConsistencyProofRequest
	0, // 8: dev.sigstore.rekor.v2.Log.GetLogInfo:output_type -> dev.sigstore.rekor.v2.LogInfo
	4, // 9: dev.sigstore.rekor.v2.Log.GetLogPublicKey:output_type -> dev.sigstore.rekor.v2.LogPublicKey
	6, // 10: dev.sigstore.rekor.v2.Log.GetConsistencyProof:output_type -> dev.sigstore.rekor.v2.ConsistencyProof
	8, // [8:11] is the sub-list for method output_type
	5, // [5:8] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_rekor_log_proto_init() }
func file_rekor_log_proto_init() {
	if File_rekor_log_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rekor_log_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogInfo); i {
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
		file_rekor_log_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TreeID); i {
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
		file_rekor_log_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogShardInfo); i {
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
		file_rekor_log_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetLogPublicKeyRequest); i {
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
		file_rekor_log_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogPublicKey); i {
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
		file_rekor_log_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetConsistencyProofRequest); i {
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
		file_rekor_log_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConsistencyProof); i {
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
			RawDescriptor: file_rekor_log_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rekor_log_proto_goTypes,
		DependencyIndexes: file_rekor_log_proto_depIdxs,
		MessageInfos:      file_rekor_log_proto_msgTypes,
	}.Build()
	File_rekor_log_proto = out.File
	file_rekor_log_proto_rawDesc = nil
	file_rekor_log_proto_goTypes = nil
	file_rekor_log_proto_depIdxs = nil
}
