// Copyright 2019-2021 The Inspektor Gadget authors
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
// 	protoc-gen-go v1.28.0
// 	protoc        v3.17.3
// source: api/gadgettracermanager.proto

package gadgettracermanager

import (
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

type Label struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *Label) Reset() {
	*x = Label{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_gadgettracermanager_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Label) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Label) ProtoMessage() {}

func (x *Label) ProtoReflect() protoreflect.Message {
	mi := &file_api_gadgettracermanager_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Label.ProtoReflect.Descriptor instead.
func (*Label) Descriptor() ([]byte, []int) {
	return file_api_gadgettracermanager_proto_rawDescGZIP(), []int{0}
}

func (x *Label) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Label) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

type AddContainerResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Debug string `protobuf:"bytes,1,opt,name=debug,proto3" json:"debug,omitempty"`
}

func (x *AddContainerResponse) Reset() {
	*x = AddContainerResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_gadgettracermanager_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddContainerResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddContainerResponse) ProtoMessage() {}

func (x *AddContainerResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_gadgettracermanager_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddContainerResponse.ProtoReflect.Descriptor instead.
func (*AddContainerResponse) Descriptor() ([]byte, []int) {
	return file_api_gadgettracermanager_proto_rawDescGZIP(), []int{1}
}

func (x *AddContainerResponse) GetDebug() string {
	if x != nil {
		return x.Debug
	}
	return ""
}

type RemoveContainerResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Debug string `protobuf:"bytes,1,opt,name=debug,proto3" json:"debug,omitempty"`
}

func (x *RemoveContainerResponse) Reset() {
	*x = RemoveContainerResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_gadgettracermanager_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RemoveContainerResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RemoveContainerResponse) ProtoMessage() {}

func (x *RemoveContainerResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_gadgettracermanager_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RemoveContainerResponse.ProtoReflect.Descriptor instead.
func (*RemoveContainerResponse) Descriptor() ([]byte, []int) {
	return file_api_gadgettracermanager_proto_rawDescGZIP(), []int{2}
}

func (x *RemoveContainerResponse) GetDebug() string {
	if x != nil {
		return x.Debug
	}
	return ""
}

type TracerID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *TracerID) Reset() {
	*x = TracerID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_gadgettracermanager_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TracerID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TracerID) ProtoMessage() {}

func (x *TracerID) ProtoReflect() protoreflect.Message {
	mi := &file_api_gadgettracermanager_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TracerID.ProtoReflect.Descriptor instead.
func (*TracerID) Descriptor() ([]byte, []int) {
	return file_api_gadgettracermanager_proto_rawDescGZIP(), []int{3}
}

func (x *TracerID) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type StreamData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Line string `protobuf:"bytes,1,opt,name=line,proto3" json:"line,omitempty"`
}

func (x *StreamData) Reset() {
	*x = StreamData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_gadgettracermanager_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StreamData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StreamData) ProtoMessage() {}

func (x *StreamData) ProtoReflect() protoreflect.Message {
	mi := &file_api_gadgettracermanager_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StreamData.ProtoReflect.Descriptor instead.
func (*StreamData) Descriptor() ([]byte, []int) {
	return file_api_gadgettracermanager_proto_rawDescGZIP(), []int{4}
}

func (x *StreamData) GetLine() string {
	if x != nil {
		return x.Line
	}
	return ""
}

type OwnerReference struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Apiversion string `protobuf:"bytes,1,opt,name=apiversion,proto3" json:"apiversion,omitempty"`
	Kind       string `protobuf:"bytes,2,opt,name=kind,proto3" json:"kind,omitempty"`
	Name       string `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	Uid        string `protobuf:"bytes,4,opt,name=uid,proto3" json:"uid,omitempty"`
}

func (x *OwnerReference) Reset() {
	*x = OwnerReference{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_gadgettracermanager_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OwnerReference) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OwnerReference) ProtoMessage() {}

func (x *OwnerReference) ProtoReflect() protoreflect.Message {
	mi := &file_api_gadgettracermanager_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OwnerReference.ProtoReflect.Descriptor instead.
func (*OwnerReference) Descriptor() ([]byte, []int) {
	return file_api_gadgettracermanager_proto_rawDescGZIP(), []int{5}
}

func (x *OwnerReference) GetApiversion() string {
	if x != nil {
		return x.Apiversion
	}
	return ""
}

func (x *OwnerReference) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *OwnerReference) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *OwnerReference) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

type ContainerDefinition struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id        string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Pid       uint32 `protobuf:"varint,2,opt,name=pid,proto3" json:"pid,omitempty"`
	OciConfig string `protobuf:"bytes,3,opt,name=oci_config,json=ociConfig,proto3" json:"oci_config,omitempty"`
	// NRI and OCI hooks don't give the OCI config but give pod details
	Namespace string   `protobuf:"bytes,4,opt,name=namespace,proto3" json:"namespace,omitempty"`
	Podname   string   `protobuf:"bytes,5,opt,name=podname,proto3" json:"podname,omitempty"`
	Name      string   `protobuf:"bytes,6,opt,name=name,proto3" json:"name,omitempty"`
	Labels    []*Label `protobuf:"bytes,7,rep,name=labels,proto3" json:"labels,omitempty"`
}

func (x *ContainerDefinition) Reset() {
	*x = ContainerDefinition{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_gadgettracermanager_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ContainerDefinition) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerDefinition) ProtoMessage() {}

func (x *ContainerDefinition) ProtoReflect() protoreflect.Message {
	mi := &file_api_gadgettracermanager_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerDefinition.ProtoReflect.Descriptor instead.
func (*ContainerDefinition) Descriptor() ([]byte, []int) {
	return file_api_gadgettracermanager_proto_rawDescGZIP(), []int{6}
}

func (x *ContainerDefinition) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ContainerDefinition) GetPid() uint32 {
	if x != nil {
		return x.Pid
	}
	return 0
}

func (x *ContainerDefinition) GetOciConfig() string {
	if x != nil {
		return x.OciConfig
	}
	return ""
}

func (x *ContainerDefinition) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *ContainerDefinition) GetPodname() string {
	if x != nil {
		return x.Podname
	}
	return ""
}

func (x *ContainerDefinition) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ContainerDefinition) GetLabels() []*Label {
	if x != nil {
		return x.Labels
	}
	return nil
}

type DumpStateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DumpStateRequest) Reset() {
	*x = DumpStateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_gadgettracermanager_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DumpStateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DumpStateRequest) ProtoMessage() {}

func (x *DumpStateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_gadgettracermanager_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DumpStateRequest.ProtoReflect.Descriptor instead.
func (*DumpStateRequest) Descriptor() ([]byte, []int) {
	return file_api_gadgettracermanager_proto_rawDescGZIP(), []int{7}
}

type Dump struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Containers string `protobuf:"bytes,1,opt,name=containers,proto3" json:"containers,omitempty"`
	Traces     string `protobuf:"bytes,2,opt,name=traces,proto3" json:"traces,omitempty"`
	Stacks     string `protobuf:"bytes,3,opt,name=stacks,proto3" json:"stacks,omitempty"`
}

func (x *Dump) Reset() {
	*x = Dump{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_gadgettracermanager_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Dump) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Dump) ProtoMessage() {}

func (x *Dump) ProtoReflect() protoreflect.Message {
	mi := &file_api_gadgettracermanager_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Dump.ProtoReflect.Descriptor instead.
func (*Dump) Descriptor() ([]byte, []int) {
	return file_api_gadgettracermanager_proto_rawDescGZIP(), []int{8}
}

func (x *Dump) GetContainers() string {
	if x != nil {
		return x.Containers
	}
	return ""
}

func (x *Dump) GetTraces() string {
	if x != nil {
		return x.Traces
	}
	return ""
}

func (x *Dump) GetStacks() string {
	if x != nil {
		return x.Stacks
	}
	return ""
}

var File_api_gadgettracermanager_proto protoreflect.FileDescriptor

var file_api_gadgettracermanager_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x72, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x13, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x6d, 0x61, 0x6e,
	0x61, 0x67, 0x65, 0x72, 0x22, 0x2f, 0x0a, 0x05, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x12, 0x10, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x2c, 0x0a, 0x14, 0x41, 0x64, 0x64, 0x43, 0x6f, 0x6e, 0x74,
	0x61, 0x69, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a,
	0x05, 0x64, 0x65, 0x62, 0x75, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x64, 0x65,
	0x62, 0x75, 0x67, 0x22, 0x2f, 0x0a, 0x17, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x6f, 0x6e,
	0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14,
	0x0a, 0x05, 0x64, 0x65, 0x62, 0x75, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x64,
	0x65, 0x62, 0x75, 0x67, 0x22, 0x1a, 0x0a, 0x08, 0x54, 0x72, 0x61, 0x63, 0x65, 0x72, 0x49, 0x44,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64,
	0x22, 0x20, 0x0a, 0x0a, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x44, 0x61, 0x74, 0x61, 0x12, 0x12,
	0x0a, 0x04, 0x6c, 0x69, 0x6e, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6c, 0x69,
	0x6e, 0x65, 0x22, 0x6a, 0x0a, 0x0e, 0x4f, 0x77, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x66, 0x65, 0x72,
	0x65, 0x6e, 0x63, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x61, 0x70, 0x69, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x61, 0x70, 0x69, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x6b, 0x69, 0x6e, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x10, 0x0a, 0x03,
	0x75, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x69, 0x64, 0x22, 0xd6,
	0x01, 0x0a, 0x13, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x44, 0x65, 0x66, 0x69,
	0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x70, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x03, 0x70, 0x69, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x6f, 0x63, 0x69, 0x5f,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6f, 0x63,
	0x69, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65,
	0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x6f, 0x64, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x6f, 0x64, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x32, 0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x07, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x72, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x52,
	0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x22, 0x12, 0x0a, 0x10, 0x44, 0x75, 0x6d, 0x70, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x56, 0x0a, 0x04, 0x44,
	0x75, 0x6d, 0x70, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e,
	0x65, 0x72, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x72, 0x61, 0x63, 0x65, 0x73, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x72, 0x61, 0x63, 0x65, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x73,
	0x74, 0x61, 0x63, 0x6b, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x74, 0x61,
	0x63, 0x6b, 0x73, 0x32, 0x8f, 0x03, 0x0a, 0x13, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x54, 0x72,
	0x61, 0x63, 0x65, 0x72, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x12, 0x53, 0x0a, 0x0d, 0x52,
	0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x12, 0x1d, 0x2e, 0x67,
	0x61, 0x64, 0x67, 0x65, 0x74, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x61, 0x67,
	0x65, 0x72, 0x2e, 0x54, 0x72, 0x61, 0x63, 0x65, 0x72, 0x49, 0x44, 0x1a, 0x1f, 0x2e, 0x67, 0x61,
	0x64, 0x67, 0x65, 0x74, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65,
	0x72, 0x2e, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x44, 0x61, 0x74, 0x61, 0x22, 0x00, 0x30, 0x01,
	0x12, 0x65, 0x0a, 0x0c, 0x41, 0x64, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x12, 0x28, 0x2e, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x6d,
	0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x29, 0x2e, 0x67, 0x61, 0x64,
	0x67, 0x65, 0x74, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72,
	0x2e, 0x41, 0x64, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x6b, 0x0a, 0x0f, 0x52, 0x65, 0x6d, 0x6f, 0x76,
	0x65, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12, 0x28, 0x2e, 0x67, 0x61, 0x64,
	0x67, 0x65, 0x74, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72,
	0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69,
	0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x2c, 0x2e, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74, 0x74, 0x72, 0x61,
	0x63, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x52, 0x65, 0x6d, 0x6f, 0x76,
	0x65, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x00, 0x12, 0x4f, 0x0a, 0x09, 0x44, 0x75, 0x6d, 0x70, 0x53, 0x74, 0x61, 0x74,
	0x65, 0x12, 0x25, 0x2e, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72,
	0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x44, 0x75, 0x6d, 0x70, 0x53, 0x74, 0x61, 0x74,
	0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x67, 0x61, 0x64, 0x67, 0x65,
	0x74, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x44,
	0x75, 0x6d, 0x70, 0x22, 0x00, 0x42, 0x46, 0x5a, 0x44, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x6e, 0x73, 0x70, 0x65, 0x6b, 0x74, 0x6f, 0x72, 0x2d, 0x67, 0x61,
	0x64, 0x67, 0x65, 0x74, 0x2f, 0x69, 0x6e, 0x73, 0x70, 0x65, 0x6b, 0x74, 0x6f, 0x72, 0x2d, 0x67,
	0x61, 0x64, 0x67, 0x65, 0x74, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74,
	0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_gadgettracermanager_proto_rawDescOnce sync.Once
	file_api_gadgettracermanager_proto_rawDescData = file_api_gadgettracermanager_proto_rawDesc
)

func file_api_gadgettracermanager_proto_rawDescGZIP() []byte {
	file_api_gadgettracermanager_proto_rawDescOnce.Do(func() {
		file_api_gadgettracermanager_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_gadgettracermanager_proto_rawDescData)
	})
	return file_api_gadgettracermanager_proto_rawDescData
}

var file_api_gadgettracermanager_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_api_gadgettracermanager_proto_goTypes = []interface{}{
	(*Label)(nil),                   // 0: gadgettracermanager.Label
	(*AddContainerResponse)(nil),    // 1: gadgettracermanager.AddContainerResponse
	(*RemoveContainerResponse)(nil), // 2: gadgettracermanager.RemoveContainerResponse
	(*TracerID)(nil),                // 3: gadgettracermanager.TracerID
	(*StreamData)(nil),              // 4: gadgettracermanager.StreamData
	(*OwnerReference)(nil),          // 5: gadgettracermanager.OwnerReference
	(*ContainerDefinition)(nil),     // 6: gadgettracermanager.ContainerDefinition
	(*DumpStateRequest)(nil),        // 7: gadgettracermanager.DumpStateRequest
	(*Dump)(nil),                    // 8: gadgettracermanager.Dump
}
var file_api_gadgettracermanager_proto_depIdxs = []int32{
	0, // 0: gadgettracermanager.ContainerDefinition.labels:type_name -> gadgettracermanager.Label
	3, // 1: gadgettracermanager.GadgetTracerManager.ReceiveStream:input_type -> gadgettracermanager.TracerID
	6, // 2: gadgettracermanager.GadgetTracerManager.AddContainer:input_type -> gadgettracermanager.ContainerDefinition
	6, // 3: gadgettracermanager.GadgetTracerManager.RemoveContainer:input_type -> gadgettracermanager.ContainerDefinition
	7, // 4: gadgettracermanager.GadgetTracerManager.DumpState:input_type -> gadgettracermanager.DumpStateRequest
	4, // 5: gadgettracermanager.GadgetTracerManager.ReceiveStream:output_type -> gadgettracermanager.StreamData
	1, // 6: gadgettracermanager.GadgetTracerManager.AddContainer:output_type -> gadgettracermanager.AddContainerResponse
	2, // 7: gadgettracermanager.GadgetTracerManager.RemoveContainer:output_type -> gadgettracermanager.RemoveContainerResponse
	8, // 8: gadgettracermanager.GadgetTracerManager.DumpState:output_type -> gadgettracermanager.Dump
	5, // [5:9] is the sub-list for method output_type
	1, // [1:5] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_api_gadgettracermanager_proto_init() }
func file_api_gadgettracermanager_proto_init() {
	if File_api_gadgettracermanager_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_gadgettracermanager_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Label); i {
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
		file_api_gadgettracermanager_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddContainerResponse); i {
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
		file_api_gadgettracermanager_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RemoveContainerResponse); i {
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
		file_api_gadgettracermanager_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TracerID); i {
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
		file_api_gadgettracermanager_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StreamData); i {
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
		file_api_gadgettracermanager_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OwnerReference); i {
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
		file_api_gadgettracermanager_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ContainerDefinition); i {
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
		file_api_gadgettracermanager_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DumpStateRequest); i {
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
		file_api_gadgettracermanager_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Dump); i {
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
			RawDescriptor: file_api_gadgettracermanager_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_gadgettracermanager_proto_goTypes,
		DependencyIndexes: file_api_gadgettracermanager_proto_depIdxs,
		MessageInfos:      file_api_gadgettracermanager_proto_msgTypes,
	}.Build()
	File_api_gadgettracermanager_proto = out.File
	file_api_gadgettracermanager_proto_rawDesc = nil
	file_api_gadgettracermanager_proto_goTypes = nil
	file_api_gadgettracermanager_proto_depIdxs = nil
}
