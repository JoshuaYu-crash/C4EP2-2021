# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: transinfo.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='transinfo.proto',
  package='transinfo',
  syntax='proto3',
  serialized_options=b'\n\032io.grpc.examples.transinfoB\016TransInfoProtoP\001\242\002\003TIP',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0ftransinfo.proto\x12\ttransinfo\"\xd8\x01\n\x0bInfoSending\x12\x0c\n\x04type\x18\x01 \x01(\t\x12\x10\n\x08protocol\x18\x02 \x01(\t\x12\r\n\x05saddr\x18\x03 \x01(\t\x12\r\n\x05sport\x18\x04 \x01(\x05\x12\x11\n\tsend_byte\x18\x05 \x01(\x05\x12\r\n\x05\x64\x61\x64\x64r\x18\x06 \x01(\t\x12\r\n\x05\x64port\x18\x07 \x01(\x05\x12\x11\n\trecv_byte\x18\x08 \x01(\x05\x12\x0c\n\x04time\x18\t \x01(\x05\x12\x0b\n\x03pid\x18\n \x01(\x05\x12\x0b\n\x03\x63om\x18\x0b \x01(\t\x12\x0c\n\x04host\x18\x0c \x01(\t\x12\x11\n\tprev_time\x18\r \x01(\x05\"1\n\x0cSuccessReply\x12\r\n\x05reply\x18\x01 \x01(\t\x12\x12\n\nreply_code\x18\x02 \x01(\x05\x32I\n\tTransInfo\x12<\n\x07GetInfo\x12\x16.transinfo.InfoSending\x1a\x17.transinfo.SuccessReply\"\x00\x42\x34\n\x1aio.grpc.examples.transinfoB\x0eTransInfoProtoP\x01\xa2\x02\x03TIPb\x06proto3'
)




_INFOSENDING = _descriptor.Descriptor(
  name='InfoSending',
  full_name='transinfo.InfoSending',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='transinfo.InfoSending.type', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='protocol', full_name='transinfo.InfoSending.protocol', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='saddr', full_name='transinfo.InfoSending.saddr', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='sport', full_name='transinfo.InfoSending.sport', index=3,
      number=4, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='send_byte', full_name='transinfo.InfoSending.send_byte', index=4,
      number=5, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='daddr', full_name='transinfo.InfoSending.daddr', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='dport', full_name='transinfo.InfoSending.dport', index=6,
      number=7, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='recv_byte', full_name='transinfo.InfoSending.recv_byte', index=7,
      number=8, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='time', full_name='transinfo.InfoSending.time', index=8,
      number=9, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pid', full_name='transinfo.InfoSending.pid', index=9,
      number=10, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='com', full_name='transinfo.InfoSending.com', index=10,
      number=11, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='host', full_name='transinfo.InfoSending.host', index=11,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='prev_time', full_name='transinfo.InfoSending.prev_time', index=12,
      number=13, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=31,
  serialized_end=247,
)


_SUCCESSREPLY = _descriptor.Descriptor(
  name='SuccessReply',
  full_name='transinfo.SuccessReply',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='reply', full_name='transinfo.SuccessReply.reply', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='reply_code', full_name='transinfo.SuccessReply.reply_code', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=249,
  serialized_end=298,
)

DESCRIPTOR.message_types_by_name['InfoSending'] = _INFOSENDING
DESCRIPTOR.message_types_by_name['SuccessReply'] = _SUCCESSREPLY
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

InfoSending = _reflection.GeneratedProtocolMessageType('InfoSending', (_message.Message,), {
  'DESCRIPTOR' : _INFOSENDING,
  '__module__' : 'transinfo_pb2'
  # @@protoc_insertion_point(class_scope:transinfo.InfoSending)
  })
_sym_db.RegisterMessage(InfoSending)

SuccessReply = _reflection.GeneratedProtocolMessageType('SuccessReply', (_message.Message,), {
  'DESCRIPTOR' : _SUCCESSREPLY,
  '__module__' : 'transinfo_pb2'
  # @@protoc_insertion_point(class_scope:transinfo.SuccessReply)
  })
_sym_db.RegisterMessage(SuccessReply)


DESCRIPTOR._options = None

_TRANSINFO = _descriptor.ServiceDescriptor(
  name='TransInfo',
  full_name='transinfo.TransInfo',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_start=300,
  serialized_end=373,
  methods=[
  _descriptor.MethodDescriptor(
    name='GetInfo',
    full_name='transinfo.TransInfo.GetInfo',
    index=0,
    containing_service=None,
    input_type=_INFOSENDING,
    output_type=_SUCCESSREPLY,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
])
_sym_db.RegisterServiceDescriptor(_TRANSINFO)

DESCRIPTOR.services_by_name['TransInfo'] = _TRANSINFO

# @@protoc_insertion_point(module_scope)
