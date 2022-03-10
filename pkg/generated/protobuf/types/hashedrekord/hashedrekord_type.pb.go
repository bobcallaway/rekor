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
// 	protoc        v3.19.4
// source: pkg/types/hashedrekord/hashedrekord_type.proto

package hashedrekord

import (
	types "github.com/sigstore/rekor/pkg/generated/protobuf/types"
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

type ProposedEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseType  *types.BaseType `protobuf:"bytes,1,opt,name=baseType,proto3" json:"baseType,omitempty"`
	Hash      string          `protobuf:"bytes,2,opt,name=hash,proto3" json:"hash,omitempty"`
	Signature []byte          `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
	PublicKey []byte          `protobuf:"bytes,4,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
}

func (x *ProposedEntry) Reset() {
	*x = ProposedEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_types_hashedrekord_hashedrekord_type_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProposedEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProposedEntry) ProtoMessage() {}

func (x *ProposedEntry) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_types_hashedrekord_hashedrekord_type_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProposedEntry.ProtoReflect.Descriptor instead.
func (*ProposedEntry) Descriptor() ([]byte, []int) {
	return file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDescGZIP(), []int{0}
}

func (x *ProposedEntry) GetBaseType() *types.BaseType {
	if x != nil {
		return x.BaseType
	}
	return nil
}

func (x *ProposedEntry) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

func (x *ProposedEntry) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *ProposedEntry) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

//
// Canonicalized entry from log
type Entry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Something string `protobuf:"bytes,1,opt,name=something,proto3" json:"something,omitempty"`
}

func (x *Entry) Reset() {
	*x = Entry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_types_hashedrekord_hashedrekord_type_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Entry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Entry) ProtoMessage() {}

func (x *Entry) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_types_hashedrekord_hashedrekord_type_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Entry.ProtoReflect.Descriptor instead.
func (*Entry) Descriptor() ([]byte, []int) {
	return file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDescGZIP(), []int{1}
}

func (x *Entry) GetSomething() string {
	if x != nil {
		return x.Something
	}
	return ""
}

var File_pkg_types_hashedrekord_hashedrekord_type_proto protoreflect.FileDescriptor

var file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDesc = []byte{
	0x0a, 0x2e, 0x70, 0x6b, 0x67, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x68, 0x61, 0x73, 0x68,
	0x65, 0x64, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x64, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x72,
	0x65, 0x6b, 0x6f, 0x72, 0x64, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x25, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72,
	0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x68, 0x61, 0x73, 0x68, 0x65,
	0x64, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x64, 0x1a, 0x19, 0x70, 0x6b, 0x67, 0x2f, 0x74, 0x79, 0x70,
	0x65, 0x73, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x9f, 0x01, 0x0a, 0x0d, 0x50, 0x72, 0x6f, 0x70, 0x6f, 0x73, 0x65, 0x64, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x3e, 0x0a, 0x08, 0x62, 0x61, 0x73, 0x65, 0x54, 0x79, 0x70, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x74, 0x79, 0x70, 0x65,
	0x73, 0x2e, 0x42, 0x61, 0x73, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x08, 0x62, 0x61, 0x73, 0x65,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x4b, 0x65, 0x79, 0x22, 0x25, 0x0a, 0x05, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x1c, 0x0a,
	0x09, 0x73, 0x6f, 0x6d, 0x65, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x73, 0x6f, 0x6d, 0x65, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x42, 0x45, 0x5a, 0x43, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f,
	0x72, 0x65, 0x2f, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x65, 0x6e,
	0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x72, 0x65, 0x6b, 0x6f,
	0x72, 0x64, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDescOnce sync.Once
	file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDescData = file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDesc
)

func file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDescGZIP() []byte {
	file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDescOnce.Do(func() {
		file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDescData)
	})
	return file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDescData
}

var file_pkg_types_hashedrekord_hashedrekord_type_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_pkg_types_hashedrekord_hashedrekord_type_proto_goTypes = []interface{}{
	(*ProposedEntry)(nil),  // 0: dev.sigstore.rekor.types.hashedrekord.ProposedEntry
	(*Entry)(nil),          // 1: dev.sigstore.rekor.types.hashedrekord.Entry
	(*types.BaseType)(nil), // 2: dev.sigstore.rekor.types.BaseType
}
var file_pkg_types_hashedrekord_hashedrekord_type_proto_depIdxs = []int32{
	2, // 0: dev.sigstore.rekor.types.hashedrekord.ProposedEntry.baseType:type_name -> dev.sigstore.rekor.types.BaseType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_pkg_types_hashedrekord_hashedrekord_type_proto_init() }
func file_pkg_types_hashedrekord_hashedrekord_type_proto_init() {
	if File_pkg_types_hashedrekord_hashedrekord_type_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_types_hashedrekord_hashedrekord_type_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProposedEntry); i {
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
		file_pkg_types_hashedrekord_hashedrekord_type_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Entry); i {
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
			RawDescriptor: file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_types_hashedrekord_hashedrekord_type_proto_goTypes,
		DependencyIndexes: file_pkg_types_hashedrekord_hashedrekord_type_proto_depIdxs,
		MessageInfos:      file_pkg_types_hashedrekord_hashedrekord_type_proto_msgTypes,
	}.Build()
	File_pkg_types_hashedrekord_hashedrekord_type_proto = out.File
	file_pkg_types_hashedrekord_hashedrekord_type_proto_rawDesc = nil
	file_pkg_types_hashedrekord_hashedrekord_type_proto_goTypes = nil
	file_pkg_types_hashedrekord_hashedrekord_type_proto_depIdxs = nil
}
