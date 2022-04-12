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
// source: pkg/types/intoto/intoto.proto

package intoto

import (
	common "github.com/sigstore/rekor/pkg/generated/protobuf/common"
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

//
// ProposedIntoto represents the structure of the message required to present to Rekor
// to make an entry of the Intoto type.
type ProposedIntoto struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// DSSE envelope encompassing the entire Intoto statement
	Envelope []byte `protobuf:"bytes,1,opt,name=envelope,proto3" json:"envelope,omitempty"`
	//
	// Public key used to verify signature(s) over envelope
	PublicKey *common.PublicKey `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
}

func (x *ProposedIntoto) Reset() {
	*x = ProposedIntoto{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_types_intoto_intoto_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProposedIntoto) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProposedIntoto) ProtoMessage() {}

func (x *ProposedIntoto) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_types_intoto_intoto_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProposedIntoto.ProtoReflect.Descriptor instead.
func (*ProposedIntoto) Descriptor() ([]byte, []int) {
	return file_pkg_types_intoto_intoto_proto_rawDescGZIP(), []int{0}
}

func (x *ProposedIntoto) GetEnvelope() []byte {
	if x != nil {
		return x.Envelope
	}
	return nil
}

func (x *ProposedIntoto) GetPublicKey() *common.PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

//
// Intoto represents the structure of the entry persisted in the transparency log for
// the Intoto type.
type Intoto struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// Public key used to verify signature(s) over envelope
	PublicKey *common.PublicKey `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	//
	// Digest over entire envelope
	EnvelopeHash *common.Hash `protobuf:"bytes,2,opt,name=envelope_hash,json=envelopeHash,proto3" json:"envelope_hash,omitempty"`
	//
	// Digest over envelope payload
	PayloadHash *common.Hash `protobuf:"bytes,3,opt,name=payload_hash,json=payloadHash,proto3" json:"payload_hash,omitempty"`
}

func (x *Intoto) Reset() {
	*x = Intoto{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_types_intoto_intoto_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Intoto) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Intoto) ProtoMessage() {}

func (x *Intoto) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_types_intoto_intoto_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Intoto.ProtoReflect.Descriptor instead.
func (*Intoto) Descriptor() ([]byte, []int) {
	return file_pkg_types_intoto_intoto_proto_rawDescGZIP(), []int{1}
}

func (x *Intoto) GetPublicKey() *common.PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *Intoto) GetEnvelopeHash() *common.Hash {
	if x != nil {
		return x.EnvelopeHash
	}
	return nil
}

func (x *Intoto) GetPayloadHash() *common.Hash {
	if x != nil {
		return x.PayloadHash
	}
	return nil
}

var File_pkg_types_intoto_intoto_proto protoreflect.FileDescriptor

var file_pkg_types_intoto_intoto_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x70, 0x6b, 0x67, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x69, 0x6e, 0x74, 0x6f,
	0x74, 0x6f, 0x2f, 0x69, 0x6e, 0x74, 0x6f, 0x74, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x22, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65,
	0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x69, 0x6e, 0x74,
	0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x5f, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x7e, 0x0a, 0x0e, 0x50, 0x72, 0x6f, 0x70,
	0x6f, 0x73, 0x65, 0x64, 0x49, 0x6e, 0x74, 0x6f, 0x74, 0x6f, 0x12, 0x1f, 0x0a, 0x08, 0x65, 0x6e,
	0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x03, 0xe0, 0x41,
	0x02, 0x52, 0x08, 0x65, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x12, 0x4b, 0x0a, 0x0a, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x27, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72,
	0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x50,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x09, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x22, 0xe0, 0x01, 0x0a, 0x06, 0x49, 0x6e, 0x74,
	0x6f, 0x74, 0x6f, 0x12, 0x46, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69,
	0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79,
	0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x47, 0x0a, 0x0d, 0x65,
	0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x22, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72,
	0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x48, 0x61, 0x73, 0x68, 0x52, 0x0c, 0x65, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65,
	0x48, 0x61, 0x73, 0x68, 0x12, 0x45, 0x0a, 0x0c, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x5f,
	0x68, 0x61, 0x73, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x64, 0x65, 0x76,
	0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f, 0x72, 0x2e,
	0x76, 0x32, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x48, 0x61, 0x73, 0x68, 0x52, 0x0b,
	0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x48, 0x61, 0x73, 0x68, 0x42, 0x77, 0x0a, 0x22, 0x64,
	0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x72, 0x65, 0x6b, 0x6f,
	0x72, 0x2e, 0x76, 0x32, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x69, 0x6e, 0x74, 0x6f, 0x74,
	0x6f, 0x42, 0x10, 0x52, 0x65, 0x6b, 0x6f, 0x72, 0x49, 0x6e, 0x74, 0x6f, 0x74, 0x6f, 0x50, 0x72,
	0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x3d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x72, 0x65, 0x6b, 0x6f, 0x72,
	0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x69, 0x6e,
	0x74, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_types_intoto_intoto_proto_rawDescOnce sync.Once
	file_pkg_types_intoto_intoto_proto_rawDescData = file_pkg_types_intoto_intoto_proto_rawDesc
)

func file_pkg_types_intoto_intoto_proto_rawDescGZIP() []byte {
	file_pkg_types_intoto_intoto_proto_rawDescOnce.Do(func() {
		file_pkg_types_intoto_intoto_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_types_intoto_intoto_proto_rawDescData)
	})
	return file_pkg_types_intoto_intoto_proto_rawDescData
}

var file_pkg_types_intoto_intoto_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_pkg_types_intoto_intoto_proto_goTypes = []interface{}{
	(*ProposedIntoto)(nil),   // 0: dev.sigstore.rekor.v2.types.intoto.ProposedIntoto
	(*Intoto)(nil),           // 1: dev.sigstore.rekor.v2.types.intoto.Intoto
	(*common.PublicKey)(nil), // 2: dev.sigstore.rekor.v2.common.PublicKey
	(*common.Hash)(nil),      // 3: dev.sigstore.rekor.v2.common.Hash
}
var file_pkg_types_intoto_intoto_proto_depIdxs = []int32{
	2, // 0: dev.sigstore.rekor.v2.types.intoto.ProposedIntoto.public_key:type_name -> dev.sigstore.rekor.v2.common.PublicKey
	2, // 1: dev.sigstore.rekor.v2.types.intoto.Intoto.public_key:type_name -> dev.sigstore.rekor.v2.common.PublicKey
	3, // 2: dev.sigstore.rekor.v2.types.intoto.Intoto.envelope_hash:type_name -> dev.sigstore.rekor.v2.common.Hash
	3, // 3: dev.sigstore.rekor.v2.types.intoto.Intoto.payload_hash:type_name -> dev.sigstore.rekor.v2.common.Hash
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_pkg_types_intoto_intoto_proto_init() }
func file_pkg_types_intoto_intoto_proto_init() {
	if File_pkg_types_intoto_intoto_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_types_intoto_intoto_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProposedIntoto); i {
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
		file_pkg_types_intoto_intoto_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Intoto); i {
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
			RawDescriptor: file_pkg_types_intoto_intoto_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_types_intoto_intoto_proto_goTypes,
		DependencyIndexes: file_pkg_types_intoto_intoto_proto_depIdxs,
		MessageInfos:      file_pkg_types_intoto_intoto_proto_msgTypes,
	}.Build()
	File_pkg_types_intoto_intoto_proto = out.File
	file_pkg_types_intoto_intoto_proto_rawDesc = nil
	file_pkg_types_intoto_intoto_proto_goTypes = nil
	file_pkg_types_intoto_intoto_proto_depIdxs = nil
}
