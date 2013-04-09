/* Generated by the protocol buffer compiler.  DO NOT EDIT! */

#ifndef PROTOBUF_C_descriptor_2eproto__INCLUDED
#define PROTOBUF_C_descriptor_2eproto__INCLUDED

#include "protobuf-c.h"

PROTOBUF_C_BEGIN_DECLS


typedef struct _Google__Protobuf__FileDescriptorSet Google__Protobuf__FileDescriptorSet;
typedef struct _Google__Protobuf__FileDescriptorProto Google__Protobuf__FileDescriptorProto;
typedef struct _Google__Protobuf__DescriptorProto Google__Protobuf__DescriptorProto;
typedef struct _Google__Protobuf__DescriptorProto__ExtensionRange Google__Protobuf__DescriptorProto__ExtensionRange;
typedef struct _Google__Protobuf__FieldDescriptorProto Google__Protobuf__FieldDescriptorProto;
typedef struct _Google__Protobuf__EnumDescriptorProto Google__Protobuf__EnumDescriptorProto;
typedef struct _Google__Protobuf__EnumValueDescriptorProto Google__Protobuf__EnumValueDescriptorProto;
typedef struct _Google__Protobuf__ServiceDescriptorProto Google__Protobuf__ServiceDescriptorProto;
typedef struct _Google__Protobuf__MethodDescriptorProto Google__Protobuf__MethodDescriptorProto;
typedef struct _Google__Protobuf__FileOptions Google__Protobuf__FileOptions;
typedef struct _Google__Protobuf__MessageOptions Google__Protobuf__MessageOptions;
typedef struct _Google__Protobuf__FieldOptions Google__Protobuf__FieldOptions;
typedef struct _Google__Protobuf__EnumOptions Google__Protobuf__EnumOptions;
typedef struct _Google__Protobuf__EnumValueOptions Google__Protobuf__EnumValueOptions;
typedef struct _Google__Protobuf__ServiceOptions Google__Protobuf__ServiceOptions;
typedef struct _Google__Protobuf__MethodOptions Google__Protobuf__MethodOptions;
typedef struct _Google__Protobuf__UninterpretedOption Google__Protobuf__UninterpretedOption;
typedef struct _Google__Protobuf__UninterpretedOption__NamePart Google__Protobuf__UninterpretedOption__NamePart;


/* --- enums --- */

typedef enum _Google__Protobuf__FieldDescriptorProto__Type {
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_DOUBLE = 1,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_FLOAT = 2,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_INT64 = 3,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_UINT64 = 4,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_INT32 = 5,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_FIXED64 = 6,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_FIXED32 = 7,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_BOOL = 8,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_STRING = 9,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_GROUP = 10,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_MESSAGE = 11,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_BYTES = 12,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_UINT32 = 13,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_ENUM = 14,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_SFIXED32 = 15,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_SFIXED64 = 16,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_SINT32 = 17,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__TYPE__TYPE_SINT64 = 18
} Google__Protobuf__FieldDescriptorProto__Type;
typedef enum _Google__Protobuf__FieldDescriptorProto__Label {
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__LABEL__LABEL_OPTIONAL = 1,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__LABEL__LABEL_REQUIRED = 2,
  GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__LABEL__LABEL_REPEATED = 3
} Google__Protobuf__FieldDescriptorProto__Label;
typedef enum _Google__Protobuf__FileOptions__OptimizeMode {
  GOOGLE__PROTOBUF__FILE_OPTIONS__OPTIMIZE_MODE__SPEED = 1,
  GOOGLE__PROTOBUF__FILE_OPTIONS__OPTIMIZE_MODE__CODE_SIZE = 2
} Google__Protobuf__FileOptions__OptimizeMode;
typedef enum _Google__Protobuf__FieldOptions__CType {
  GOOGLE__PROTOBUF__FIELD_OPTIONS__CTYPE__CORD = 1,
  GOOGLE__PROTOBUF__FIELD_OPTIONS__CTYPE__STRING_PIECE = 2
} Google__Protobuf__FieldOptions__CType;

/* --- messages --- */

struct  _Google__Protobuf__FileDescriptorSet
{
  ProtobufCMessage base;
  size_t n_file;
  Google__Protobuf__FileDescriptorProto **file;
};
#define GOOGLE__PROTOBUF__FILE_DESCRIPTOR_SET__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__file_descriptor_set__descriptor) \
    , 0,NULL }


struct  _Google__Protobuf__FileDescriptorProto
{
  ProtobufCMessage base;
  char *name;
  char *package;
  size_t n_dependency;
  char **dependency;
  size_t n_message_type;
  Google__Protobuf__DescriptorProto **message_type;
  size_t n_enum_type;
  Google__Protobuf__EnumDescriptorProto **enum_type;
  size_t n_service;
  Google__Protobuf__ServiceDescriptorProto **service;
  size_t n_extension;
  Google__Protobuf__FieldDescriptorProto **extension;
  Google__Protobuf__FileOptions *options;
};
#define GOOGLE__PROTOBUF__FILE_DESCRIPTOR_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__file_descriptor_proto__descriptor) \
    , NULL, NULL, 0,NULL, 0,NULL, 0,NULL, 0,NULL, 0,NULL, NULL }


struct  _Google__Protobuf__DescriptorProto__ExtensionRange
{
  ProtobufCMessage base;
  protobuf_c_boolean has_start;
  int32_t start;
  protobuf_c_boolean has_end;
  int32_t end;
};
#define GOOGLE__PROTOBUF__DESCRIPTOR_PROTO__EXTENSION_RANGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__descriptor_proto__extension_range__descriptor) \
    , 0,0, 0,0 }


struct  _Google__Protobuf__DescriptorProto
{
  ProtobufCMessage base;
  char *name;
  size_t n_field;
  Google__Protobuf__FieldDescriptorProto **field;
  size_t n_extension;
  Google__Protobuf__FieldDescriptorProto **extension;
  size_t n_nested_type;
  Google__Protobuf__DescriptorProto **nested_type;
  size_t n_enum_type;
  Google__Protobuf__EnumDescriptorProto **enum_type;
  size_t n_extension_range;
  Google__Protobuf__DescriptorProto__ExtensionRange **extension_range;
  Google__Protobuf__MessageOptions *options;
};
#define GOOGLE__PROTOBUF__DESCRIPTOR_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__descriptor_proto__descriptor) \
    , NULL, 0,NULL, 0,NULL, 0,NULL, 0,NULL, 0,NULL, NULL }


struct  _Google__Protobuf__FieldDescriptorProto
{
  ProtobufCMessage base;
  char *name;
  protobuf_c_boolean has_number;
  int32_t number;
  protobuf_c_boolean has_label;
  Google__Protobuf__FieldDescriptorProto__Label label;
  protobuf_c_boolean has_type;
  Google__Protobuf__FieldDescriptorProto__Type type;
  char *type_name;
  char *extendee;
  char *default_value;
  Google__Protobuf__FieldOptions *options;
};
#define GOOGLE__PROTOBUF__FIELD_DESCRIPTOR_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__field_descriptor_proto__descriptor) \
    , NULL, 0,0, 0,0, 0,0, NULL, NULL, NULL, NULL }


struct  _Google__Protobuf__EnumDescriptorProto
{
  ProtobufCMessage base;
  char *name;
  size_t n_value;
  Google__Protobuf__EnumValueDescriptorProto **value;
  Google__Protobuf__EnumOptions *options;
};
#define GOOGLE__PROTOBUF__ENUM_DESCRIPTOR_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__enum_descriptor_proto__descriptor) \
    , NULL, 0,NULL, NULL }


struct  _Google__Protobuf__EnumValueDescriptorProto
{
  ProtobufCMessage base;
  char *name;
  protobuf_c_boolean has_number;
  int32_t number;
  Google__Protobuf__EnumValueOptions *options;
};
#define GOOGLE__PROTOBUF__ENUM_VALUE_DESCRIPTOR_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__enum_value_descriptor_proto__descriptor) \
    , NULL, 0,0, NULL }


struct  _Google__Protobuf__ServiceDescriptorProto
{
  ProtobufCMessage base;
  char *name;
  size_t n_method;
  Google__Protobuf__MethodDescriptorProto **method;
  Google__Protobuf__ServiceOptions *options;
};
#define GOOGLE__PROTOBUF__SERVICE_DESCRIPTOR_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__service_descriptor_proto__descriptor) \
    , NULL, 0,NULL, NULL }


struct  _Google__Protobuf__MethodDescriptorProto
{
  ProtobufCMessage base;
  char *name;
  char *input_type;
  char *output_type;
  Google__Protobuf__MethodOptions *options;
};
#define GOOGLE__PROTOBUF__METHOD_DESCRIPTOR_PROTO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__method_descriptor_proto__descriptor) \
    , NULL, NULL, NULL, NULL }


struct  _Google__Protobuf__FileOptions
{
  ProtobufCMessage base;
  char *java_package;
  char *java_outer_classname;
  protobuf_c_boolean has_java_multiple_files;
  protobuf_c_boolean java_multiple_files;
  protobuf_c_boolean has_optimize_for;
  Google__Protobuf__FileOptions__OptimizeMode optimize_for;
  size_t n_uninterpreted_option;
  Google__Protobuf__UninterpretedOption **uninterpreted_option;
};
#define GOOGLE__PROTOBUF__FILE_OPTIONS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__file_options__descriptor) \
    , NULL, NULL, 0,0, 0,GOOGLE__PROTOBUF__FILE_OPTIONS__OPTIMIZE_MODE__CODE_SIZE, 0,NULL }


struct  _Google__Protobuf__MessageOptions
{
  ProtobufCMessage base;
  protobuf_c_boolean has_message_set_wire_format;
  protobuf_c_boolean message_set_wire_format;
  size_t n_uninterpreted_option;
  Google__Protobuf__UninterpretedOption **uninterpreted_option;
};
#define GOOGLE__PROTOBUF__MESSAGE_OPTIONS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__message_options__descriptor) \
    , 0,0, 0,NULL }


struct  _Google__Protobuf__FieldOptions
{
  ProtobufCMessage base;
  protobuf_c_boolean has_ctype;
  Google__Protobuf__FieldOptions__CType ctype;
  char *experimental_map_key;
  size_t n_uninterpreted_option;
  Google__Protobuf__UninterpretedOption **uninterpreted_option;
};
#define GOOGLE__PROTOBUF__FIELD_OPTIONS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__field_options__descriptor) \
    , 0,0, NULL, 0,NULL }


struct  _Google__Protobuf__EnumOptions
{
  ProtobufCMessage base;
  size_t n_uninterpreted_option;
  Google__Protobuf__UninterpretedOption **uninterpreted_option;
};
#define GOOGLE__PROTOBUF__ENUM_OPTIONS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__enum_options__descriptor) \
    , 0,NULL }


struct  _Google__Protobuf__EnumValueOptions
{
  ProtobufCMessage base;
  size_t n_uninterpreted_option;
  Google__Protobuf__UninterpretedOption **uninterpreted_option;
};
#define GOOGLE__PROTOBUF__ENUM_VALUE_OPTIONS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__enum_value_options__descriptor) \
    , 0,NULL }


struct  _Google__Protobuf__ServiceOptions
{
  ProtobufCMessage base;
  size_t n_uninterpreted_option;
  Google__Protobuf__UninterpretedOption **uninterpreted_option;
};
#define GOOGLE__PROTOBUF__SERVICE_OPTIONS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__service_options__descriptor) \
    , 0,NULL }


struct  _Google__Protobuf__MethodOptions
{
  ProtobufCMessage base;
  size_t n_uninterpreted_option;
  Google__Protobuf__UninterpretedOption **uninterpreted_option;
};
#define GOOGLE__PROTOBUF__METHOD_OPTIONS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__method_options__descriptor) \
    , 0,NULL }


struct  _Google__Protobuf__UninterpretedOption__NamePart
{
  ProtobufCMessage base;
  char *name_part;
  protobuf_c_boolean is_extension;
};
#define GOOGLE__PROTOBUF__UNINTERPRETED_OPTION__NAME_PART__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__uninterpreted_option__name_part__descriptor) \
    , NULL, 0 }


struct  _Google__Protobuf__UninterpretedOption
{
  ProtobufCMessage base;
  size_t n_name;
  Google__Protobuf__UninterpretedOption__NamePart **name;
  char *identifier_value;
  protobuf_c_boolean has_positive_int_value;
  uint64_t positive_int_value;
  protobuf_c_boolean has_negative_int_value;
  int64_t negative_int_value;
  protobuf_c_boolean has_double_value;
  double double_value;
  protobuf_c_boolean has_string_value;
  ProtobufCBinaryData string_value;
};
#define GOOGLE__PROTOBUF__UNINTERPRETED_OPTION__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&google__protobuf__uninterpreted_option__descriptor) \
    , 0,NULL, NULL, 0,0, 0,0, 0,0, 0,{0,NULL} }


/* Google__Protobuf__FileDescriptorSet methods */
void   google__protobuf__file_descriptor_set__init
                     (Google__Protobuf__FileDescriptorSet         *message);
size_t google__protobuf__file_descriptor_set__get_packed_size
                     (const Google__Protobuf__FileDescriptorSet   *message);
size_t google__protobuf__file_descriptor_set__pack
                     (const Google__Protobuf__FileDescriptorSet   *message,
                      uint8_t             *out);
size_t google__protobuf__file_descriptor_set__pack_to_buffer
                     (const Google__Protobuf__FileDescriptorSet   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__FileDescriptorSet *
       google__protobuf__file_descriptor_set__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__file_descriptor_set__free_unpacked
                     (Google__Protobuf__FileDescriptorSet *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__FileDescriptorProto methods */
void   google__protobuf__file_descriptor_proto__init
                     (Google__Protobuf__FileDescriptorProto         *message);
size_t google__protobuf__file_descriptor_proto__get_packed_size
                     (const Google__Protobuf__FileDescriptorProto   *message);
size_t google__protobuf__file_descriptor_proto__pack
                     (const Google__Protobuf__FileDescriptorProto   *message,
                      uint8_t             *out);
size_t google__protobuf__file_descriptor_proto__pack_to_buffer
                     (const Google__Protobuf__FileDescriptorProto   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__FileDescriptorProto *
       google__protobuf__file_descriptor_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__file_descriptor_proto__free_unpacked
                     (Google__Protobuf__FileDescriptorProto *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__DescriptorProto__ExtensionRange methods */
void   google__protobuf__descriptor_proto__extension_range__init
                     (Google__Protobuf__DescriptorProto__ExtensionRange         *message);
/* Google__Protobuf__DescriptorProto methods */
void   google__protobuf__descriptor_proto__init
                     (Google__Protobuf__DescriptorProto         *message);
size_t google__protobuf__descriptor_proto__get_packed_size
                     (const Google__Protobuf__DescriptorProto   *message);
size_t google__protobuf__descriptor_proto__pack
                     (const Google__Protobuf__DescriptorProto   *message,
                      uint8_t             *out);
size_t google__protobuf__descriptor_proto__pack_to_buffer
                     (const Google__Protobuf__DescriptorProto   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__DescriptorProto *
       google__protobuf__descriptor_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__descriptor_proto__free_unpacked
                     (Google__Protobuf__DescriptorProto *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__FieldDescriptorProto methods */
void   google__protobuf__field_descriptor_proto__init
                     (Google__Protobuf__FieldDescriptorProto         *message);
size_t google__protobuf__field_descriptor_proto__get_packed_size
                     (const Google__Protobuf__FieldDescriptorProto   *message);
size_t google__protobuf__field_descriptor_proto__pack
                     (const Google__Protobuf__FieldDescriptorProto   *message,
                      uint8_t             *out);
size_t google__protobuf__field_descriptor_proto__pack_to_buffer
                     (const Google__Protobuf__FieldDescriptorProto   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__FieldDescriptorProto *
       google__protobuf__field_descriptor_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__field_descriptor_proto__free_unpacked
                     (Google__Protobuf__FieldDescriptorProto *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__EnumDescriptorProto methods */
void   google__protobuf__enum_descriptor_proto__init
                     (Google__Protobuf__EnumDescriptorProto         *message);
size_t google__protobuf__enum_descriptor_proto__get_packed_size
                     (const Google__Protobuf__EnumDescriptorProto   *message);
size_t google__protobuf__enum_descriptor_proto__pack
                     (const Google__Protobuf__EnumDescriptorProto   *message,
                      uint8_t             *out);
size_t google__protobuf__enum_descriptor_proto__pack_to_buffer
                     (const Google__Protobuf__EnumDescriptorProto   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__EnumDescriptorProto *
       google__protobuf__enum_descriptor_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__enum_descriptor_proto__free_unpacked
                     (Google__Protobuf__EnumDescriptorProto *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__EnumValueDescriptorProto methods */
void   google__protobuf__enum_value_descriptor_proto__init
                     (Google__Protobuf__EnumValueDescriptorProto         *message);
size_t google__protobuf__enum_value_descriptor_proto__get_packed_size
                     (const Google__Protobuf__EnumValueDescriptorProto   *message);
size_t google__protobuf__enum_value_descriptor_proto__pack
                     (const Google__Protobuf__EnumValueDescriptorProto   *message,
                      uint8_t             *out);
size_t google__protobuf__enum_value_descriptor_proto__pack_to_buffer
                     (const Google__Protobuf__EnumValueDescriptorProto   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__EnumValueDescriptorProto *
       google__protobuf__enum_value_descriptor_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__enum_value_descriptor_proto__free_unpacked
                     (Google__Protobuf__EnumValueDescriptorProto *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__ServiceDescriptorProto methods */
void   google__protobuf__service_descriptor_proto__init
                     (Google__Protobuf__ServiceDescriptorProto         *message);
size_t google__protobuf__service_descriptor_proto__get_packed_size
                     (const Google__Protobuf__ServiceDescriptorProto   *message);
size_t google__protobuf__service_descriptor_proto__pack
                     (const Google__Protobuf__ServiceDescriptorProto   *message,
                      uint8_t             *out);
size_t google__protobuf__service_descriptor_proto__pack_to_buffer
                     (const Google__Protobuf__ServiceDescriptorProto   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__ServiceDescriptorProto *
       google__protobuf__service_descriptor_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__service_descriptor_proto__free_unpacked
                     (Google__Protobuf__ServiceDescriptorProto *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__MethodDescriptorProto methods */
void   google__protobuf__method_descriptor_proto__init
                     (Google__Protobuf__MethodDescriptorProto         *message);
size_t google__protobuf__method_descriptor_proto__get_packed_size
                     (const Google__Protobuf__MethodDescriptorProto   *message);
size_t google__protobuf__method_descriptor_proto__pack
                     (const Google__Protobuf__MethodDescriptorProto   *message,
                      uint8_t             *out);
size_t google__protobuf__method_descriptor_proto__pack_to_buffer
                     (const Google__Protobuf__MethodDescriptorProto   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__MethodDescriptorProto *
       google__protobuf__method_descriptor_proto__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__method_descriptor_proto__free_unpacked
                     (Google__Protobuf__MethodDescriptorProto *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__FileOptions methods */
void   google__protobuf__file_options__init
                     (Google__Protobuf__FileOptions         *message);
size_t google__protobuf__file_options__get_packed_size
                     (const Google__Protobuf__FileOptions   *message);
size_t google__protobuf__file_options__pack
                     (const Google__Protobuf__FileOptions   *message,
                      uint8_t             *out);
size_t google__protobuf__file_options__pack_to_buffer
                     (const Google__Protobuf__FileOptions   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__FileOptions *
       google__protobuf__file_options__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__file_options__free_unpacked
                     (Google__Protobuf__FileOptions *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__MessageOptions methods */
void   google__protobuf__message_options__init
                     (Google__Protobuf__MessageOptions         *message);
size_t google__protobuf__message_options__get_packed_size
                     (const Google__Protobuf__MessageOptions   *message);
size_t google__protobuf__message_options__pack
                     (const Google__Protobuf__MessageOptions   *message,
                      uint8_t             *out);
size_t google__protobuf__message_options__pack_to_buffer
                     (const Google__Protobuf__MessageOptions   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__MessageOptions *
       google__protobuf__message_options__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__message_options__free_unpacked
                     (Google__Protobuf__MessageOptions *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__FieldOptions methods */
void   google__protobuf__field_options__init
                     (Google__Protobuf__FieldOptions         *message);
size_t google__protobuf__field_options__get_packed_size
                     (const Google__Protobuf__FieldOptions   *message);
size_t google__protobuf__field_options__pack
                     (const Google__Protobuf__FieldOptions   *message,
                      uint8_t             *out);
size_t google__protobuf__field_options__pack_to_buffer
                     (const Google__Protobuf__FieldOptions   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__FieldOptions *
       google__protobuf__field_options__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__field_options__free_unpacked
                     (Google__Protobuf__FieldOptions *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__EnumOptions methods */
void   google__protobuf__enum_options__init
                     (Google__Protobuf__EnumOptions         *message);
size_t google__protobuf__enum_options__get_packed_size
                     (const Google__Protobuf__EnumOptions   *message);
size_t google__protobuf__enum_options__pack
                     (const Google__Protobuf__EnumOptions   *message,
                      uint8_t             *out);
size_t google__protobuf__enum_options__pack_to_buffer
                     (const Google__Protobuf__EnumOptions   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__EnumOptions *
       google__protobuf__enum_options__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__enum_options__free_unpacked
                     (Google__Protobuf__EnumOptions *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__EnumValueOptions methods */
void   google__protobuf__enum_value_options__init
                     (Google__Protobuf__EnumValueOptions         *message);
size_t google__protobuf__enum_value_options__get_packed_size
                     (const Google__Protobuf__EnumValueOptions   *message);
size_t google__protobuf__enum_value_options__pack
                     (const Google__Protobuf__EnumValueOptions   *message,
                      uint8_t             *out);
size_t google__protobuf__enum_value_options__pack_to_buffer
                     (const Google__Protobuf__EnumValueOptions   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__EnumValueOptions *
       google__protobuf__enum_value_options__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__enum_value_options__free_unpacked
                     (Google__Protobuf__EnumValueOptions *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__ServiceOptions methods */
void   google__protobuf__service_options__init
                     (Google__Protobuf__ServiceOptions         *message);
size_t google__protobuf__service_options__get_packed_size
                     (const Google__Protobuf__ServiceOptions   *message);
size_t google__protobuf__service_options__pack
                     (const Google__Protobuf__ServiceOptions   *message,
                      uint8_t             *out);
size_t google__protobuf__service_options__pack_to_buffer
                     (const Google__Protobuf__ServiceOptions   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__ServiceOptions *
       google__protobuf__service_options__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__service_options__free_unpacked
                     (Google__Protobuf__ServiceOptions *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__MethodOptions methods */
void   google__protobuf__method_options__init
                     (Google__Protobuf__MethodOptions         *message);
size_t google__protobuf__method_options__get_packed_size
                     (const Google__Protobuf__MethodOptions   *message);
size_t google__protobuf__method_options__pack
                     (const Google__Protobuf__MethodOptions   *message,
                      uint8_t             *out);
size_t google__protobuf__method_options__pack_to_buffer
                     (const Google__Protobuf__MethodOptions   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__MethodOptions *
       google__protobuf__method_options__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__method_options__free_unpacked
                     (Google__Protobuf__MethodOptions *message,
                      ProtobufCAllocator *allocator);
/* Google__Protobuf__UninterpretedOption__NamePart methods */
void   google__protobuf__uninterpreted_option__name_part__init
                     (Google__Protobuf__UninterpretedOption__NamePart         *message);
/* Google__Protobuf__UninterpretedOption methods */
void   google__protobuf__uninterpreted_option__init
                     (Google__Protobuf__UninterpretedOption         *message);
size_t google__protobuf__uninterpreted_option__get_packed_size
                     (const Google__Protobuf__UninterpretedOption   *message);
size_t google__protobuf__uninterpreted_option__pack
                     (const Google__Protobuf__UninterpretedOption   *message,
                      uint8_t             *out);
size_t google__protobuf__uninterpreted_option__pack_to_buffer
                     (const Google__Protobuf__UninterpretedOption   *message,
                      ProtobufCBuffer     *buffer);
Google__Protobuf__UninterpretedOption *
       google__protobuf__uninterpreted_option__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   google__protobuf__uninterpreted_option__free_unpacked
                     (Google__Protobuf__UninterpretedOption *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Google__Protobuf__FileDescriptorSet_Closure)
                 (const Google__Protobuf__FileDescriptorSet *message,
                  void *closure_data);
typedef void (*Google__Protobuf__FileDescriptorProto_Closure)
                 (const Google__Protobuf__FileDescriptorProto *message,
                  void *closure_data);
typedef void (*Google__Protobuf__DescriptorProto__ExtensionRange_Closure)
                 (const Google__Protobuf__DescriptorProto__ExtensionRange *message,
                  void *closure_data);
typedef void (*Google__Protobuf__DescriptorProto_Closure)
                 (const Google__Protobuf__DescriptorProto *message,
                  void *closure_data);
typedef void (*Google__Protobuf__FieldDescriptorProto_Closure)
                 (const Google__Protobuf__FieldDescriptorProto *message,
                  void *closure_data);
typedef void (*Google__Protobuf__EnumDescriptorProto_Closure)
                 (const Google__Protobuf__EnumDescriptorProto *message,
                  void *closure_data);
typedef void (*Google__Protobuf__EnumValueDescriptorProto_Closure)
                 (const Google__Protobuf__EnumValueDescriptorProto *message,
                  void *closure_data);
typedef void (*Google__Protobuf__ServiceDescriptorProto_Closure)
                 (const Google__Protobuf__ServiceDescriptorProto *message,
                  void *closure_data);
typedef void (*Google__Protobuf__MethodDescriptorProto_Closure)
                 (const Google__Protobuf__MethodDescriptorProto *message,
                  void *closure_data);
typedef void (*Google__Protobuf__FileOptions_Closure)
                 (const Google__Protobuf__FileOptions *message,
                  void *closure_data);
typedef void (*Google__Protobuf__MessageOptions_Closure)
                 (const Google__Protobuf__MessageOptions *message,
                  void *closure_data);
typedef void (*Google__Protobuf__FieldOptions_Closure)
                 (const Google__Protobuf__FieldOptions *message,
                  void *closure_data);
typedef void (*Google__Protobuf__EnumOptions_Closure)
                 (const Google__Protobuf__EnumOptions *message,
                  void *closure_data);
typedef void (*Google__Protobuf__EnumValueOptions_Closure)
                 (const Google__Protobuf__EnumValueOptions *message,
                  void *closure_data);
typedef void (*Google__Protobuf__ServiceOptions_Closure)
                 (const Google__Protobuf__ServiceOptions *message,
                  void *closure_data);
typedef void (*Google__Protobuf__MethodOptions_Closure)
                 (const Google__Protobuf__MethodOptions *message,
                  void *closure_data);
typedef void (*Google__Protobuf__UninterpretedOption__NamePart_Closure)
                 (const Google__Protobuf__UninterpretedOption__NamePart *message,
                  void *closure_data);
typedef void (*Google__Protobuf__UninterpretedOption_Closure)
                 (const Google__Protobuf__UninterpretedOption *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor google__protobuf__file_descriptor_set__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__file_descriptor_proto__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__descriptor_proto__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__descriptor_proto__extension_range__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__field_descriptor_proto__descriptor;
extern const ProtobufCEnumDescriptor    google__protobuf__field_descriptor_proto__type__descriptor;
extern const ProtobufCEnumDescriptor    google__protobuf__field_descriptor_proto__label__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__enum_descriptor_proto__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__enum_value_descriptor_proto__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__service_descriptor_proto__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__method_descriptor_proto__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__file_options__descriptor;
extern const ProtobufCEnumDescriptor    google__protobuf__file_options__optimize_mode__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__message_options__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__field_options__descriptor;
extern const ProtobufCEnumDescriptor    google__protobuf__field_options__ctype__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__enum_options__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__enum_value_options__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__service_options__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__method_options__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__uninterpreted_option__descriptor;
extern const ProtobufCMessageDescriptor google__protobuf__uninterpreted_option__name_part__descriptor;

PROTOBUF_C_END_DECLS


#endif  /* PROTOBUF_descriptor_2eproto__INCLUDED */
